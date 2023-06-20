#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/unistd.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include "interceptor.h"


MODULE_DESCRIPTION("My kernel module");
MODULE_AUTHOR("Your name here ...");
MODULE_LICENSE("GPL");

//----- System Call Table Stuff ------------------------------------
/* Symbol that allows access to the kernel system call table */
extern void* sys_call_table[];
//以标示变量或者函数的定义在别的文件中，提示编译器遇到此变量和函数时在其他模块中寻找其定义

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	pte->pte = pte->pte &~_PAGE_RW;

}

struct pid_list {
	pid_t pid;
	struct list_head list;
};


/* Store info about intercepted/replaced system calls */
typedef struct {

	/* Original system call */
	asmlinkage long (*f)(struct pt_regs);

	/* Status: 1=intercepted, 0=not intercepted */
	int intercepted;

	/* Are any PIDs being monitored for this syscall? */
	int monitored;	
	/* List of monitored PIDs */
	int listcount;
	struct list_head my_list;
}mytable;

/* An entry for each system call in this "metadata" table */
mytable table[NR_syscalls];

/* Access to the system call table and your metadata table must be synchronized */
spinlock_t my_table_lock = SPIN_LOCK_UNLOCKED;
spinlock_t sys_call_table_lock = SPIN_LOCK_UNLOCKED;

static int add_pid_sysc(pid_t pid, int sysc)
{
	struct pid_list *ple=(struct pid_list*)kmalloc(sizeof(struct pid_list), GFP_KERNEL);

	if (!ple)
		return -ENOMEM;

	INIT_LIST_HEAD(&ple->list);
	ple->pid=pid;

	list_add(&ple->list, &(table[sysc].my_list));
	table[sysc].listcount++;

	return 0;
}

/**
 * Remove a pid from a system call's list of monitored pids.
 * Returns -EINVAL if no such pid was found in the list.
 */
static int del_pid_sysc(pid_t pid, int sysc)
{
	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid) {

			list_del(i);
			kfree(ple);

			table[sysc].listcount--;
			/* If there are no more pids in sysc's list of pids, then
			 * stop the monitoring only if it's not for all pids (monitored=2) */
			if(table[sysc].listcount == 0 && table[sysc].monitored == 1) {
				table[sysc].monitored = 0;
			}

			return 0;
		}
	}

	return -EINVAL;
}

/**
 * Remove a pid from all the lists of monitored pids (for all intercepted syscalls).
 * Returns -1 if this process is not being monitored in any list.
 */
static int del_pid(pid_t pid)
{
	struct list_head *i, *n;
	struct pid_list *ple;
	int ispid = 0, s = 0;

	for(s = 1; s < NR_syscalls; s++) {

		list_for_each_safe(i, n, &(table[s].my_list)) {

			ple=list_entry(i, struct pid_list, list);
			if(ple->pid == pid) {

				list_del(i);
				ispid = 1;
				kfree(ple);

				table[s].listcount--;
				/* If there are no more pids in sysc's list of pids, then
				 * stop the monitoring only if it's not for all pids (monitored=2) */
				if(table[s].listcount == 0 && table[s].monitored == 1) {
					table[s].monitored = 0;
				}
			}
		}
	}

	if (ispid) return 0;
	return -1;
}

/**
 * Clear the list of monitored pids for a specific syscall.
 */
static void destroy_list(int sysc) {

	struct list_head *i, *n;
	struct pid_list *ple;

	list_for_each_safe(i, n, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		list_del(i);
		kfree(ple);
	}

	table[sysc].listcount = 0;
	table[sysc].monitored = 0;
}


static int check_pids_same_owner(pid_t pid1, pid_t pid2) {

	struct task_struct *p1 = pid_task(find_vpid(pid1), PIDTYPE_PID);
	struct task_struct *p2 = pid_task(find_vpid(pid2), PIDTYPE_PID);
	if(p1->real_cred->uid != p2->real_cred->uid)
		return -EPERM;
	return 0;
}

/**
 * Check if a pid is already being monitored for a specific syscall.
 * Returns 1 if it already is, or 0 if pid is not in sysc's list.
 */
static int check_pid_monitored(int sysc, pid_t pid) {

	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid) 
			return 1;
		
	}
	return 0;	
}

asmlinkage long (*orig_exit_group)(struct pt_regs reg);


asmlinkage long my_exit_group(struct pt_regs reg)
{

	spin_lock(&my_table_lock);
	del_pid(current->pid);
	spin_unlock(&my_table_lock);
	orig_exit_group(reg);

}

asmlinkage long interceptor(struct pt_regs reg) {
	
	//we know that the system call is being intercepted (otherwise we would not reach this)
	//he log message will simply contain the system call number and the arguments, 
	//as well as the calling process's pid. 
	if (table[reg.ax].intercepted == 1){
		//all pids are monitored for this syscall
		if (table[reg.ax].monitored ==2){
			log_message(current->pid, reg.ax, reg.bx, reg.cx, reg.dx, reg.si, reg.di, reg.bp);
		// some pids are monitored, check the corresponding my_list
		}else if (table[reg.ax].monitored ==1){
			if (check_pid_monitored(reg.ax,  current -> pid) == 1){
				log_message(current->pid, reg.ax, reg.bx, reg.cx, reg.dx, reg.si, reg.di, reg.bp);
			}
		}
	} 
	// eventually call the original system call to allow normal 
	//operation of all processes in the system.
	return table[reg.ax].f(reg);
	//return 0; // Just a placeholder, so it compiles with no warnings!
}



asmlinkage long my_syscall(int cmd, int syscall, int pid) {
	//(-EINVAL):
	//The syscall number must be valid: not negative, not > NR_syscalls-1 ,not MY_CUSTOM_SYSCALL itself
	if((syscall < 0) || (syscall > NR_syscalls-1) || (syscall == MY_CUSTOM_SYSCALL)){
		return -EINVAL;
	}
	if (cmd == REQUEST_SYSCALL_INTERCEPT){
		//error condition
		// (-EPERM) we must be root (see the current_uid() macro)
		if (current_uid() != 0){
			return -EPERM;
		}
		//Check for -EBUSY conditions:
		//If intercepting a system call that is already intercepted.
		if (table[syscall].intercepted == 1){
			return -EBUSY;
		}	
		//intercept the 'syscall' argument
		//the corresponding entry in the system call table will be replaced with a generic interceptor function  
		//and the original system call will be saved.
		spin_lock(&my_table_lock);
		spin_lock(&sys_call_table_lock);
		//original

		table[syscall].f = sys_call_table[syscall];
		table[syscall].intercepted = 1;
		set_addr_rw((unsigned long)sys_call_table);
		sys_call_table[syscall] = interceptor;
		set_addr_ro((unsigned long)sys_call_table);

		spin_unlock(&my_table_lock);
		spin_unlock(&sys_call_table_lock);
	}
	else if (cmd == REQUEST_SYSCALL_RELEASE){
		//error condition
		// (-EPERM) we must be root (see the current_uid() macro)
		if (current_uid() != 0){
			return -EPERM;
		}
		//Cannot de-intercept a system call that has not been intercepted yet.
		if (table[syscall].intercepted == 0){
			return -EINVAL;
		}	
		
		
		//REQUEST_SYSCALL_RELEASE command is issued, 
		//the original saved system call is restored in the system call table 
		//in its corresponding position.
		spin_lock(&my_table_lock);
		spin_lock(&sys_call_table_lock);
		//original

		
		table[syscall].intercepted = 0;
		// 是否把monitored也变0?
		destroy_list(syscall);
		set_addr_rw((unsigned long)sys_call_table);
		sys_call_table[syscall] = table[syscall].f;
		set_addr_ro((unsigned long)sys_call_table);

		spin_unlock(&my_table_lock);
		spin_unlock(&sys_call_table_lock);
	}


	if(cmd == REQUEST_START_MONITORING){
//		//be existing pid (except for the case when it's 0,
//		//indicating that we want to start/stop monitoring for all pids).
//		//If a pid belongs to a valid process, pid_task(find_vpid(pid), PIDTYPE_PID) not null
//		if(pid<0 || (pid !=0 && pid_task(find_vpid(pid), PIDTYPE_PID)== NULL)){
//		    printk(KERN_DEBUG"E invalid");
//			return -EINVAL;
//		}
//
//        //calling process is root, no doubts about permissions.
//        //If it is not, then check if the pid requested is owned by the calling process
//        if (current_uid() != 0 ){
//            printk(KERN_DEBUG"2 invalid");
//            return -EPERM;
//        }
//
//		//Also, if pid is 0 and the calling process is not root, then access is denied
//		if(pid==0 && current_uid() != 0 ){
//            printk(KERN_DEBUG"3 invalid");
//			return -EPERM;
//		}
//		//If the system call has not been intercepted yet,
//		// a command to start monitoring a pid for that syscall is also invalid.
//		if(table[syscall].intercepted != 1){
//            printk(KERN_DEBUG"4 invalid");
//			return -EINVAL;
//		}
//		//If monitoring a pid that is already being monitored.
//		if(table[syscall].monitored != 0 && check_pid_monitored(syscall, pid)==1){
//            printk(KERN_DEBUG"5 invalid");
//			return  -EBUSY;
//		}
//		//If a pid cannot be added to a monitored list,
//		//due to no memory being available, an -ENOMEM error code should be returned.
//		//The starter code provides a set of functions that enable operation with kernel lists.
//
//		//add pid to the syscall's list of monitored PIDs.
//		// A special case is that if pid is 0 then all processes are monitored
//		//for syscall, but only root has the permission to issue this command
//
//
//		spin_lock(&my_table_lock);
//		spin_lock(&sys_call_table_lock);
//
//		//original
//		if(pid == 0 && current_uid() == 0){//存疑
//			if(table[syscall].monitored == 2){
//				spin_unlock(&my_table_lock);
//				spin_unlock(&sys_call_table_lock);
//				return -EBUSY;
//			}else{
//				table[syscall].monitored =2;
//			}
//
//		}
//		if(pid != 0){
//			if(table[syscall].monitored == 2){
//				spin_unlock(&my_table_lock);
//				spin_unlock(&sys_call_table_lock);
//				return -EBUSY;
//			}else if(add_pid_sysc(pid, syscall)!=0){
//				spin_unlock(&my_table_lock);
//				spin_unlock(&sys_call_table_lock);
//				return -ENOMEM;
//
//			}else{
//				table[syscall].monitored =1;
//			}
//
//		}
//
//		spin_unlock(&my_table_lock);
//		spin_unlock(&sys_call_table_lock);
        if (pid < 0 || (pid != 0 && pid_task(find_vpid(pid), PIDTYPE_PID) == NULL))
        {
            return -EINVAL;
        }
        spin_lock(&my_table_lock);
        if (pid == 0)
        {

            if (current_uid() != 0)
            {
                spin_unlock(&my_table_lock);
                return -EPERM;
            }
            if (table[syscall].monitored == 2)
            {
                spin_unlock(&my_table_lock);
                return -EBUSY;
            }
            else
            {
                table[syscall].monitored = 2;
                spin_unlock(&my_table_lock);
            }
        }
        else
        {
            if (current_uid() == 0 || check_pids_same_owner(pid, current->pid) == 0)
            {

                if (check_pid_monitored(syscall, pid) != 0)
                {

                    return -EBUSY;
                }
                else if (add_pid_sysc(pid, syscall) != 0)
                {

                    return -ENOMEM;
                }
                spin_lock(&my_table_lock);
                if (table[syscall].monitored = 0)
                {
                    table[syscall].monitored = 1;

                }
                spin_unlock(&my_table_lock);
            }
            else
            {
                return -EPERM;
            }
        }
	}

	if(cmd == REQUEST_STOP_MONITORING){
//		//be existing pid (except for the case when it's 0,
//		//indicating that we want to start/stop monitoring for all pids).
//		//If a pid belongs to a valid process, pid_task(find_vpid(pid), PIDTYPE_PID) not null
//		if(pid<0 ||( pid !=0 && pid_task(find_vpid(pid), PIDTYPE_PID)== NULL )){
//            printk(KERN_DEBUG"1 invalid");
//		    return -EINVAL;
//		}
//		//calling process is root, no doubts about permissions.
//		//If it is not, then check if the pid requested is owned by the calling process
//		//存疑 pid是否也要等于0
//		if (current_uid() != 0 && check_pids_same_owner(pid, current->pid)!=0){
//            printk(KERN_DEBUG"2 invalid");
//		    return -EPERM;
//		}
//		//Also, if pid is 0 and the calling process is not root, then access is denied
//		if(pid==0 && current_uid() != 0 ){
//            printk(KERN_DEBUG"3 invalid");
//		    return -EPERM;
//		}
//		//Cannot stop monitoring for a pid that is not being monitored,
//		// or if the system call has not been intercepted ye
//		if(table[syscall].intercepted != 1 || check_pid_monitored(syscall,  pid)==0){
//            printk(KERN_DEBUG"4 invalid");
//		    return -EINVAL;
//		}
//
//		//stop monitoring process pid for system call syscall,
//		// i.e., remove pid from the syscall's list of monitored PIDs.
//
//		// hijack the exit_group system call (with number __NR_exit_group),
//		//by replacing it in the system call table with your own custom function my_exit_group.
//		//Of course, make sure to save the original exit_group function, and to restore it
//		//when your kernel module is unloaded.
//
//
//        spin_lock(&my_table_lock);
//        spin_lock(&sys_call_table_lock);
//
//		//original
//		if(pid == 0 ){//存疑
//			if(current_uid() == 0){
//				destroy_list(syscall);
//				table[syscall].monitored = 0;
//			}else{
//				spin_unlock(&my_table_lock);
//				spin_unlock(&sys_call_table_lock);
//				return -EPERM;
//				}
//			}
//		if(pid != 0){
//			del_pid_sysc(pid, syscall);
//		}
//        spin_unlock(&my_table_lock);
//        spin_unlock(&sys_call_table_lock);

        if (pid < 0 || (pid != 0 && pid_task(find_vpid(pid), PIDTYPE_PID) == NULL))
        {
            return -EINVAL;
        }

        if (pid == 0)
        {
            spin_lock(&my_table_lock);
            if (current_uid() == 0)
            {
                destroy_list(syscall);
                table[syscall].monitored = 0;
                spin_unlock(&my_table_lock);
            }
            else
            {
                spin_unlock(&my_table_lock);

                return -EPERM;
            }
        }
        else
        {
            if (current_uid() == 0 || check_pids_same_owner(pid, current->pid) == 0)
            {

                if (check_pid_monitored(syscall, pid) != 0)
                {

                    return -EBUSY;
                }
                else if (check_pid_monitored(syscall, pid) != 1)
                { //check
                    return -EINVAL;
                }
                spin_lock(&my_table_lock);

                if (del_pid_sysc(pid, syscall) != 0)
                {
                    spin_unlock(&my_table_lock);
                    return -EINVAL;
                }
                spin_unlock(&my_table_lock);
            }
            else
            {
                return -EPERM;
            }
        }
        }

	return 0;
	}


/**
 *
 if(cmd == REQUEST_START_MONITORING){
     if(pid<0 || (pid !=0 && pid_task(find_vpid(pid), PIDTYPE_PID)== NULL )){
         return -EINVAL;
     }
     spin_lock(&my_table_lock);
     if (pid == 0){
         if(current_uid() != 0){
             spin_unlock(&my_table_lock);
             return -EPERM;
         }
         if(table[syscall].monitored == 2){
             spin_unlock(&my_table_lock);
             return -EBUSY;
         }else{
             table[syscall].monitored =2;
             spin_unlock(&my_table_lock);
         }

     }else{
         if (current_uid() == 0 || check_pids_same_owner(pid, current->pid)==0){
         
             if(check_pid_monitored(syscall, pid) != 0){
                 
                 return -EBUSY;
             }else if(add_pid_sysc(pid, syscall)!=0){
                 
                 return -ENOMEM;

             }
             spin_lock(&my_table_lock);
             if(table[syscall].monitored = 0){
                 table[syscall].monitored =1;
             spin_unlock(&my_table_lock);}
     }else{
             return -EPERM;
     }
     
     }
 }
 if(cmd == REQUEST_STOP_MONITORING){
     if(pid<0 || (pid !=0 && pid_task(find_vpid(pid), PIDTYPE_PID)== NULL )){
         return -EINVAL;
     }
     
     if (pid == 0){
         spin_lock(&my_table_lock);
         if(current_uid() == 0){
             destroy_list(syscall);
             table[syscall].monitored = 0;
             spin_unlock(&my_table_lock);
         }else{
             spin_unlock(&my_table_lock);

             return -EPERM;
             }
     }else{
         if (current_uid() == 0 || check_pids_same_owner(pid, current->pid)==0){
         
             if(check_pid_monitored(syscall, pid) != 0){
                 
                 return -EBUSY;
             }else if(check_pid_monitored(syscall,  pid)!=1){//check
                 return -EINVAL;

             }
             spin_lock(&my_table_lock);
             if(del_pid_sysc(pid, syscall)!=0){
                 spin_unlock(&my_table_lock);
                 return -EINVAL;
             }
             spin_unlock(&my_table_lock);

         }else{
                 return -EPERM;
         }
     }
         
 }
 */
long (*orig_custom_syscall)(void);



static int init_function(void) {
    int i;
    spin_lock(&my_table_lock);
    spin_lock(&sys_call_table_lock);

    // store original custom system call and original exit group
    orig_custom_syscall = sys_call_table[MY_CUSTOM_SYSCALL];
    orig_exit_group = sys_call_table[__NR_exit_group];

    // set the sys call table to be read and writable
    set_addr_rw((unsigned long)sys_call_table);

    // set the our custom sys call and exit group in sys call table
    sys_call_table[MY_CUSTOM_SYSCALL] = my_syscall;
    sys_call_table[__NR_exit_group] = my_exit_group;

    // set the sys call table to be read only
    set_addr_ro((unsigned long)sys_call_table);

    // initialize table
    for (i = 0; i < NR_syscalls; ++i) {
        table[i].f = sys_call_table[i];
        table[i].intercepted = 0;
        table[i].monitored = 0;
        table[i].listcount = 0;
        INIT_LIST_HEAD(&table[i].my_list);

    }

    // spin_unlock
    spin_unlock(&my_table_lock);
    spin_unlock(&sys_call_table_lock);
	return 0;
}


static void exit_function(void)
{
    int i;
    spin_lock(&my_table_lock);
    spin_lock(&sys_call_table_lock);

    set_addr_rw((unsigned long)sys_call_table);

    // restore MY_CUSTOM_SYSCALL and __NR_exit_group to original syscall
    sys_call_table[MY_CUSTOM_SYSCALL] = orig_custom_syscall;
    sys_call_table[__NR_exit_group] = orig_exit_group;

    set_addr_ro((unsigned long)sys_call_table);

    for(i = 0; i < NR_syscalls+1; i++) {
        if ((i!=MY_CUSTOM_SYSCALL) && (i!=__NR_exit_group) && (table[i].intercepted))
            sys_call_table[i] = table[i].f;
    }

    // spin_unlock
    spin_unlock(&my_table_lock);
    spin_unlock(&sys_call_table_lock);



}

module_init(init_function);
module_exit(exit_function);


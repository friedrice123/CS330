#include<context.h>
#include<memory.h>
#include<lib.h>
#include<entry.h>
#include<file.h>
#include<tracer.h>


///////////////////////////////////////////////////////////////////////////
////            Start of Trace buffer functionality                   /////
///////////////////////////////////////////////////////////////////////////

int is_valid_mem_range(unsigned long buff, u32 count, int access_bit)
{
        if(count < 0) {
                return 0;
        }
        if(!buff){
                return 0;
        }
        struct exec_context *current = get_current_ctx();
        if (buff >= current->mms[MM_SEG_CODE].start && buff + (unsigned long)count < current->mms[MM_SEG_CODE].next_free){
		if((current->mms[MM_SEG_CODE].access_flags & access_bit) == access_bit){
			return 1;
		}
		else {
			return 0;
		}

	}
	if (buff >= current->mms[MM_SEG_RODATA].start && buff + (unsigned long)count < current->mms[MM_SEG_RODATA].next_free){
		if((current->mms[MM_SEG_RODATA].access_flags & access_bit) == access_bit){
			return 1;
		}
		else {
			return 0;
		}

	}
	if (buff >= current->mms[MM_SEG_DATA].start && buff + (unsigned long)count < current->mms[MM_SEG_DATA].next_free){
		if((current->mms[MM_SEG_DATA].access_flags & access_bit) == access_bit){
			return 1;
		}
		else {
			return 0;
		}

	}
	if (buff >= current->mms[MM_SEG_STACK].start && buff + (unsigned long)count < current->mms[MM_SEG_STACK].end){
		if((current->mms[MM_SEG_STACK].access_flags & access_bit) == access_bit){
			return 1;
		}
		else {
			return 0;
		}

	}
        
        // Check VM Areas
        struct vm_area *vma = current->vm_area;
        while (vma->vm_next != NULL) {
                if (buff >= vma->vm_start && buff + (unsigned long)count < vma->vm_end) {
                        if((vma->access_flags &  access_bit) == access_bit){
                                return 1;
                        }
                }
                vma = vma->vm_next;
        }
        if(buff >= vma->vm_start && buff + (unsigned long)count < vma->vm_end){
		if((vma->access_flags & access_bit) == access_bit){
			return 1;
		}
	}
        
        return 0; // Invalid buffer
}



long trace_buffer_close(struct file *filep)
{
        if (filep->type != TRACE_BUFFER) {
                return -EINVAL;
        }

        struct trace_buffer_info *trace_buff = filep->trace_buffer;
        struct fileops *fops1 = filep->fops;
        if(trace_buff == NULL) {
                return -EINVAL;
        }
        if(fops1 == NULL) {
                return -EINVAL;
        }
        if(trace_buff->data == NULL) {
                return -EINVAL;
        }

        os_page_free(USER_REG, trace_buff->data);
	os_free(trace_buff, sizeof(struct trace_buffer_info));
        os_free(fops1, sizeof(struct fileops));
        os_free(filep, sizeof(struct file));

        return 0;
}



int trace_buffer_read(struct file *filep, char *buff, u32 count)
{
        if(is_valid_mem_range((unsigned long)buff, count, 2) == 0){
                return -EBADMEM;
        }
        if(filep->mode != O_READ && filep->mode != O_RDWR){
                return -EINVAL;
        }
        if(filep->type != TRACE_BUFFER) {
                return -EINVAL;
        }
        struct trace_buffer_info *trace_buff = (struct trace_buffer_info *)(filep->trace_buffer);
        if(trace_buff == NULL) {
                return -EINVAL;
        }
        u32 available_data;
        if(trace_buff->write_offset == trace_buff->read_offset && trace_buff->is_full == 0){
                return 0;
        }
        else if(trace_buff->write_offset <= trace_buff->read_offset) {
                available_data = TRACE_BUFFER_MAX_SIZE - (trace_buff->read_offset - trace_buff->write_offset);
        }
        else{
                available_data = trace_buff->write_offset - trace_buff->read_offset;
        }

        if(available_data < count) {
                count = available_data;
        }

        if(available_data <= 0) {
                return 0;
        }

        for(u32 i = 0; i < count; i++) {
                trace_buff->is_full = 0;
		buff[i] = trace_buff->data[trace_buff->read_offset];
                trace_buff->read_offset = (trace_buff->read_offset + 1) % TRACE_BUFFER_MAX_SIZE;
        }
        return count;
}

int trace_buffer_read_aux(struct file *filep, char *buff, u32 count)
{
        if(filep->mode != O_READ && filep->mode != O_RDWR){
                return -EINVAL;
        }
        if(filep->type != TRACE_BUFFER) {
                return -EINVAL;
        }
        struct trace_buffer_info *trace_buff = (struct trace_buffer_info *)(filep->trace_buffer);
        if(trace_buff == NULL) {
                return -EINVAL;
        }
        u32 available_data;
        if(trace_buff->write_offset == trace_buff->read_offset && trace_buff->is_full == 0){
                return 0;
        }
        else if(trace_buff->write_offset <= trace_buff->read_offset) {
                available_data = TRACE_BUFFER_MAX_SIZE - (trace_buff->read_offset - trace_buff->write_offset);
        }
        else{
                available_data = trace_buff->write_offset - trace_buff->read_offset;
        }

        if(available_data < count) {
                count = available_data;
        }

        if(available_data <= 0) {
                return 0;
        }

        for(u32 i = 0; i < count; i++) {
                trace_buff->is_full = 0;
		buff[i] = trace_buff->data[trace_buff->read_offset];
                trace_buff->read_offset = (trace_buff->read_offset + 1) % TRACE_BUFFER_MAX_SIZE;
        }
        return count;
}

int trace_buffer_write(struct file *filep, char *buff, u32 count)
{
        if(is_valid_mem_range((unsigned long)buff, count, 1) == 0){
                return -EBADMEM;
        }
        if(filep->mode != O_WRITE && filep->mode != O_RDWR){
                return -EINVAL;
        }
        if(filep->type != TRACE_BUFFER) {
                return -EINVAL;
        }
        struct trace_buffer_info *trace_buff = (struct trace_buffer_info *)(filep->trace_buffer);
        if(trace_buff == NULL) {
                return -EINVAL;
        }
        u32 available_space;
        if(trace_buff->write_offset == trace_buff->read_offset && trace_buff->is_full == 1){
                return 0;
        }
        else if(trace_buff->write_offset >= trace_buff->read_offset) {
                available_space = TRACE_BUFFER_MAX_SIZE - (trace_buff->write_offset - trace_buff->read_offset);
        }
        else{
                available_space = trace_buff->read_offset - trace_buff->write_offset;
        }
		if(available_space < count) {
                count = available_space;
        }

        if(available_space == 0) {
                return 0;
        }

        for(u32 i = 0; i < count; i++) {
                trace_buff->data[trace_buff->write_offset] = buff[i];
                trace_buff->write_offset = (trace_buff->write_offset + 1) % TRACE_BUFFER_MAX_SIZE;
        }

        if(trace_buff->write_offset == trace_buff->read_offset && count != 0) {
                trace_buff->is_full = 1;
        }
        return count;
}

int trace_buffer_write_aux(struct file *filep, char *buff, u32 count)
{
        if(filep->mode != O_WRITE && filep->mode != O_RDWR){
                return -EINVAL;
        }
        if(filep->type != TRACE_BUFFER) {
                return -EINVAL;
        }
        struct trace_buffer_info *trace_buff = (struct trace_buffer_info *)(filep->trace_buffer);
        if(trace_buff == NULL) {
                return -EINVAL;
        }
        u32 available_space;
        if(trace_buff->write_offset == trace_buff->read_offset && trace_buff->is_full == 1){
                return 0;
        }
        else if(trace_buff->write_offset >= trace_buff->read_offset) {
                available_space = TRACE_BUFFER_MAX_SIZE - (trace_buff->write_offset - trace_buff->read_offset);
        }
        else{
                available_space = trace_buff->read_offset - trace_buff->write_offset;
        }
		if(available_space < count) {
                count = available_space;
        }

        if(available_space == 0) {
                return 0;
        }

        for(u32 i = 0; i < count; i++) {
                trace_buff->data[trace_buff->write_offset] = buff[i];
                trace_buff->write_offset = (trace_buff->write_offset + 1) % TRACE_BUFFER_MAX_SIZE;
        }

        if(trace_buff->write_offset == trace_buff->read_offset && count != 0) {
                trace_buff->is_full = 1;
        }
        return count;
}

int sys_create_trace_buffer(struct exec_context *current, int mode)
{
        if(mode != O_READ && mode != O_WRITE && mode != O_RDWR) {
                return -EINVAL;
        }
        int fd = -1;
        for(int i = 0; i < MAX_OPEN_FILES; i++){
                if(current->files[i] == NULL) {
                        fd = i;
                        break;
                }
        }

        if(fd == -1) {
		return -EINVAL;
        }

        struct file *new_trace_buffer_file = os_alloc(sizeof(struct file));
        new_trace_buffer_file->type = TRACE_BUFFER;
        new_trace_buffer_file->mode = mode;
        new_trace_buffer_file->offp = 0;
        new_trace_buffer_file->ref_count = 1;
        new_trace_buffer_file->inode = NULL;
        new_trace_buffer_file->trace_buffer = os_alloc(sizeof(struct trace_buffer_info));
        if (new_trace_buffer_file->trace_buffer == NULL) {
                return -ENOMEM;
        }
        new_trace_buffer_file->trace_buffer->read_offset  = 0;
        new_trace_buffer_file->trace_buffer->write_offset = 0;
        new_trace_buffer_file->trace_buffer->is_full = 0;
        new_trace_buffer_file->trace_buffer->count_syscalls = 0;

        new_trace_buffer_file->trace_buffer->data = (char *) os_page_alloc(USER_REG);
        if(new_trace_buffer_file->trace_buffer->data == NULL) {
             return -ENOMEM;
        }
        struct fileops *new_trace_buffer_file_ops = os_alloc(sizeof(struct fileops));
        if(new_trace_buffer_file_ops == NULL) {
                return -ENOMEM;
        }
        new_trace_buffer_file_ops->read = trace_buffer_read;
        new_trace_buffer_file_ops->write = trace_buffer_write;
        new_trace_buffer_file_ops->lseek = NULL;
        new_trace_buffer_file_ops->close = trace_buffer_close;

        new_trace_buffer_file->fops = new_trace_buffer_file_ops;

        current->files[fd] = new_trace_buffer_file;
        
        return fd;
}
///////////////////////////////////////////////////////////////////////////
////            Start of strace functionality                         /////
///////////////////////////////////////////////////////////////////////////

int find_num_of_params(int syscall_num){
        switch(syscall_num) {
        case SYSCALL_EXIT: return 2; // exit(int)
        case SYSCALL_GETPID: return 1; // getpid()
        case SYSCALL_FORK: return 1; // fork() 
        case SYSCALL_CFORK: return 1; // cfork()
        case SYSCALL_VFORK: return 1; // vfork()
        case SYSCALL_GET_USER_P: return 1; // get_user_page_stats()
        case SYSCALL_GET_COW_F: return 1; // get_cow_fault_stats()
        case SYSCALL_SIGNAL: return 1; // signal(int, void*)
        case SYSCALL_SLEEP: return 2; // sleep(int)
        case SYSCALL_EXPAND: return 3; // expand(unsigned, int)
        case SYSCALL_CLONE: return 3; // clone(void*, long)
        case SYSCALL_DUMP_PTT: return 2; // dump_page_table(char*)
        case SYSCALL_PHYS_INFO: return 1; // physinfo()
        case SYSCALL_STATS: return 1; // get_stats()
        case SYSCALL_CONFIGURE: return 2; // configure(struct os_configs*)
        case SYSCALL_MMAP: return 5; // mmap(void*, int, int, int)
        case SYSCALL_MUNMAP: return 3; // munmap(void*, int)
        case SYSCALL_MPROTECT: return 4; // mprotect(void*, int, int)
        case SYSCALL_PMAP: return 2; // pmap(int)
        case SYSCALL_OPEN: return 3; // open(char*, int, ...)
        case SYSCALL_WRITE: return 4; // write(int, void*, int)
        case SYSCALL_READ: return 4; // read(int, void*, int)
        case SYSCALL_DUP: return 2; // dup(int)
        case SYSCALL_DUP2: return 3; // dup2(int, int)
        case SYSCALL_CLOSE: return 2; // close(int)
        case SYSCALL_LSEEK: return 4; // lseek(int, long, int)
        case SYSCALL_FTRACE: return 5; // ftrace(unsigned long, long, long, int)
	case SYSCALL_TRACE_BUFFER: return 2;
        case SYSCALL_START_STRACE: return 3; // start_strace(int, int)
        case SYSCALL_END_STRACE: return 1; // end_strace()
        case SYSCALL_STRACE: return 3; // strace(int, int)
        case SYSCALL_READ_STRACE: return 4; // read_strace(int, void*, int)
        case SYSCALL_READ_FTRACE: return 4; // read_ftrace(int, void*, int)
        default: return 0; // Unknown syscall number
    }
}

int perform_tracing(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4)
{
        struct exec_context *current = get_current_ctx();
        if (current->st_md_base->is_traced == 0 || current->st_md_base == NULL) {
                return 0;
        }
        // We have arrived here, this means that current->st_md_base is not null
        // Suppose this is called by strace so we must ignore strace+start_strace+endstrace, not write anything to the buffer
        if(syscall_num == SYSCALL_END_STRACE || syscall_num == SYSCALL_START_STRACE || syscall_num == SYSCALL_STRACE){
                return 0;
        }
        
        // Now we have ensured this is within start and end strace, so simply search for the syscall in strace list
        // If syscall found in list and we are in FILTERED_TRACING mode, add it to trace_buffer
        if(current->st_md_base->tracing_mode == FILTERED_TRACING){
                struct strace_info *current_strace = current->st_md_base->next;
                int syscall_found = 0;
                while (current_strace) {
                        if (current_strace->syscall_num == syscall_num) {
                                syscall_found = 1;
                                
                                break;
                        }
                        current_strace = current_strace->next;
                }
                if(syscall_found == 0){
                        return 0;
                }
        }

        u64 num_of_params = find_num_of_params(syscall_num);
        if(num_of_params == 0){
                return 0;
        }
        struct file* trace_buff_file = current->files[current->st_md_base->strace_fd];
        
        u64 * syscall_info_buffer = (u64 *)os_page_alloc(USER_REG);
        syscall_info_buffer[0] = num_of_params;
        syscall_info_buffer[1] = syscall_num;
        if(num_of_params-1 == 1){
                syscall_info_buffer[2] = param1;
        }
        else if( num_of_params-1 == 2){
                syscall_info_buffer[2] = param1;
                syscall_info_buffer[3] = param2;
        }
        else if( num_of_params-1 == 3){
                syscall_info_buffer[2] = param1;
                syscall_info_buffer[3] = param2;
                syscall_info_buffer[4] = param3;
        }
        else if( num_of_params-1 == 4){
                syscall_info_buffer[2] = param1;
                syscall_info_buffer[3] = param2;
                syscall_info_buffer[4] = param3;
                syscall_info_buffer[5] = param4;
        }
        trace_buffer_write_aux(trace_buff_file, (char *)syscall_info_buffer, (num_of_params+1)*8);
        trace_buff_file->trace_buffer->count_syscalls++;
        os_page_free(USER_REG, syscall_info_buffer);
        return 0; // Success
}


int sys_strace(struct exec_context *current, int syscall_num, int action)
{
        if (current == NULL) {
                return -EINVAL;
        }

        // Here we still need to figure out how to initialise
	if (current->st_md_base == NULL){
		current->st_md_base = os_alloc(sizeof(struct strace_head));
                current->st_md_base->count = 0;
                current->st_md_base->is_traced = 1;
                current->st_md_base->next = NULL;
                current->st_md_base->last = NULL;
	}

        // ADD STRACE
        if (action == ADD_STRACE) {
                if(current->st_md_base->count >= MAX_STRACE){
                        return -EINVAL;
                }
                struct strace_info *current_strace = current->st_md_base->next;
                while (current_strace) {
                        if (current_strace->syscall_num == syscall_num) {
                                return -EINVAL;
                        }
                        current_strace = current_strace->next;
                }
                // Add syscall_num to the traced list
                struct strace_info *new_strace = os_alloc(sizeof(struct strace_info));
                new_strace->syscall_num = syscall_num;
                new_strace->next = NULL;
                if (!current->st_md_base->next) {
                        current->st_md_base->next = new_strace;
                        current->st_md_base->last = new_strace;
                }
                else {
                        current->st_md_base->last->next = new_strace;
                        current->st_md_base->last = new_strace;
                }
                current->st_md_base->count++;
                return 0;
        }
        // REMOVE STRACE
        else if (action == REMOVE_STRACE) {
                struct strace_info *prev = NULL;
                struct strace_info *current_strace = current->st_md_base->next;
                struct strace_info * guy_that_gets_deleted = NULL;
                while (current_strace) {
                        if (current_strace->syscall_num == syscall_num) {
                                guy_that_gets_deleted= current_strace;
                                if (prev) {
                                        prev->next = current_strace->next;
                                        if (!prev->next) {
                                                current->st_md_base->last = prev;
                                        }
                                }
                                else {
                                        current->st_md_base->next = current_strace->next;
                                        if (!current->st_md_base->next) {
                                                current->st_md_base->last = NULL;
                                        }
                                }
                                current->st_md_base->count--;
                                os_free(guy_that_gets_deleted, sizeof(struct strace_info));
                                return 0;
                        }
                        prev = current_strace;
                        current_strace = current_strace->next;
                }
        }
        return -EINVAL;
}

int sys_read_strace(struct file *filep, char *buff, u64 count)
{
        u64 syscalls_remaining = filep->trace_buffer->count_syscalls;
        u64 bytes_read = 0;
        u64* temp_buffer = (u64 *) os_page_alloc(USER_REG);
        for(u64 i = 0; (i < count) && (i < syscalls_remaining) ; i++){
                trace_buffer_read_aux(filep,(char *)temp_buffer, 8);
                u64 num_of_params=((u64 *)temp_buffer)[0];
                for(u64 j = 0; j < num_of_params; j++){
                        trace_buffer_read_aux(filep, buff, 8);
                        buff = buff + 8;
                        bytes_read+=8;
                }
                filep->trace_buffer->count_syscalls--;
                //free the temp buffer
                os_page_free(USER_REG, temp_buffer);
        }
        return bytes_read;
}

int sys_start_strace(struct exec_context *current, int fd, int tracing_mode)
{
        if (current == NULL) return -EINVAL;
        if(tracing_mode != FULL_TRACING && tracing_mode != FILTERED_TRACING){
                return -EINVAL;
        }
	if (current->st_md_base == NULL){
		current->st_md_base = os_alloc(sizeof(struct strace_head));
                current->st_md_base->count = 0;
                current->st_md_base->is_traced = 1;
                current->st_md_base->strace_fd = fd;
                current->st_md_base->tracing_mode = tracing_mode;
                current->st_md_base->next = NULL;
                current->st_md_base->last = NULL;
	}
        else{
                // Since we need to allocate the trace buffer fd and the tracing mode to this
                current->st_md_base->strace_fd = fd;
                current->st_md_base->tracing_mode = tracing_mode;
        }
        return 0;
}

int sys_end_strace(struct exec_context *current)
{
        if (current == NULL || current->st_md_base == NULL){
		return -EINVAL;
	}
        struct strace_info *current_entry = current->st_md_base->next;
        while (current_entry != NULL) {
                struct strace_info *temp = current_entry;
                current_entry = current_entry->next;
                os_free(temp, sizeof(struct strace_info));
        }
        os_free(current->st_md_base, sizeof(struct strace_head));
        current->st_md_base = NULL;
        return 0;
}


///////////////////////////////////////////////////////////////////////////
////            Start of ftrace functionality                         /////
///////////////////////////////////////////////////////////////////////////


long do_ftrace(struct exec_context *ctx, unsigned long faddr, long action, long nargs, int fd_trace_buffer)
{
        if (ctx == NULL) {
                return -EINVAL;
        }
        if(action == ADD_FTRACE && fd_trace_buffer < 0){
                return -EINVAL;
        }
        if(action != ADD_FTRACE && action != REMOVE_FTRACE && action != ENABLE_FTRACE && 
        action != DISABLE_FTRACE && action != ENABLE_BACKTRACE && action != DISABLE_BACKTRACE){
                return -EINVAL;
        }
	if (ctx->ft_md_base == NULL){
		ctx->ft_md_base = os_alloc(sizeof(struct ftrace_head));
                ctx->ft_md_base->count = 0;
                ctx->ft_md_base->next = NULL;
                ctx->ft_md_base->last = NULL;
	}
        // ADD FTRACE
        if (action == ADD_FTRACE) {
                if(ctx->ft_md_base->count >= FTRACE_MAX){
                        return -EINVAL;
                }
                struct ftrace_info *current_ftrace = ctx->ft_md_base->next;
                while (current_ftrace) {
                        if (current_ftrace->faddr == faddr) {
                                return -EINVAL;
                        }
                        current_ftrace = current_ftrace->next;
                }
                // Add syscall_num to the traced list
                struct ftrace_info *new_ftrace = os_alloc(sizeof(struct ftrace_info));
                new_ftrace->faddr = faddr;
                new_ftrace->num_args = nargs;
                new_ftrace->fd = fd_trace_buffer;
                new_ftrace->capture_backtrace = 0;
                new_ftrace->next = NULL;
                if (!ctx->ft_md_base->next) {
                        ctx->ft_md_base->next = new_ftrace;
                        ctx->ft_md_base->last = new_ftrace;
                }
                else {
                        ctx->ft_md_base->last->next = new_ftrace;
                        ctx->ft_md_base->last = new_ftrace;
                }
                ctx->ft_md_base->count++;
                return 0;
        }
        // REMOVE FTRACE
        else if (action == REMOVE_FTRACE) {
                // Tracing enabled
                struct ftrace_info *current_ftrace = ctx->ft_md_base->next;
                while (current_ftrace) {
                        if (current_ftrace->faddr == faddr) {
                                break;
                        }
                        current_ftrace = current_ftrace->next;
                }
                if(current_ftrace == NULL){
                        return -EINVAL;
                }
                if( (((u8*)(faddr))[0] == INV_OPCODE && ((u8*)(faddr))[1] == INV_OPCODE
                 && ((u8*)(faddr))[2] == INV_OPCODE && ((u8*)(faddr))[3] == INV_OPCODE) ) {
                        ((u8*)(faddr))[0] = current_ftrace->code_backup[0];
                        ((u8*)(faddr))[1] = current_ftrace->code_backup[1];
                        ((u8*)(faddr))[2] = current_ftrace->code_backup[2];
                        ((u8*)(faddr))[3] = current_ftrace->code_backup[3];
                 }
                // Assuming its disabled
                struct ftrace_info *prev = NULL;
                current_ftrace = ctx->ft_md_base->next;
                struct ftrace_info * guy_that_gets_deleted = NULL;
                while (current_ftrace) {
                        if (current_ftrace->faddr == faddr) {
                                guy_that_gets_deleted= current_ftrace;
                                if (prev) {
                                        prev->next = current_ftrace->next;
                                        if (!prev->next) {
                                                ctx->ft_md_base->last = prev;
                                        }
                                }
                                else {
                                        ctx->ft_md_base->next = current_ftrace->next;
                                        if (!ctx->ft_md_base->next) {
                                                ctx->ft_md_base->last = NULL;
                                        }
                                }
                                ctx->ft_md_base->count--;
                                os_free(guy_that_gets_deleted, sizeof(struct ftrace_info));
                                return 0;
                        }
                        prev = current_ftrace;
                        current_ftrace = current_ftrace->next;
                }
        }
        else if (action == ENABLE_FTRACE) {
                struct ftrace_info *current_ftrace = ctx->ft_md_base->next;
                while (current_ftrace) {
                        if (current_ftrace->faddr == faddr) {
                                break;
                        }
                        current_ftrace = current_ftrace->next;
                }
                if(current_ftrace == NULL){
                        return -EINVAL;
                }
                if( !(((u8*)(faddr))[0] == INV_OPCODE && ((u8*)(faddr))[1] == INV_OPCODE
                 && ((u8*)(faddr))[2] == INV_OPCODE && ((u8*)(faddr))[3] == INV_OPCODE) ){
                        current_ftrace->code_backup[0]=((u8*)(faddr))[0];
                        current_ftrace->code_backup[1]=((u8*)(faddr))[1];
                        current_ftrace->code_backup[2]=((u8*)(faddr))[2];
                        current_ftrace->code_backup[3]=((u8*)(faddr))[3];
                }

                ((u8*)(faddr))[0] = INV_OPCODE;
                ((u8*)(faddr))[1] = INV_OPCODE;
                ((u8*)(faddr))[2] = INV_OPCODE;
                ((u8*)(faddr))[3] = INV_OPCODE;

                return 0;

        }
        else if(action == DISABLE_FTRACE){
                struct ftrace_info *current_ftrace = ctx->ft_md_base->next;
                while (current_ftrace) {
                        if (current_ftrace->faddr == faddr) {
                                break;
                        }
                        current_ftrace = current_ftrace->next;
                }
                if(current_ftrace == NULL){
                        return -EINVAL;
                }

                ((u8*)(faddr))[0] = current_ftrace->code_backup[0];
                ((u8*)(faddr))[1] = current_ftrace->code_backup[1];
                ((u8*)(faddr))[2] = current_ftrace->code_backup[2];
                ((u8*)(faddr))[3] = current_ftrace->code_backup[3];

                return 0;
        }
        else if(action == ENABLE_BACKTRACE){
                struct ftrace_info *current_ftrace = ctx->ft_md_base->next;
                while (current_ftrace) {
                        if (current_ftrace->faddr == faddr) {
                                break;
                        }
                        current_ftrace = current_ftrace->next;
                }
                if(current_ftrace == NULL){
                        return -EINVAL;
                }
                if( !(((u8*)(faddr))[0] == INV_OPCODE && ((u8*)(faddr))[1] == INV_OPCODE
                 && ((u8*)(faddr))[2] == INV_OPCODE && ((u8*)(faddr))[3] == INV_OPCODE) ){
                        current_ftrace->code_backup[0]=((u8*)(faddr))[0];
                        current_ftrace->code_backup[1]=((u8*)(faddr))[1];
                        current_ftrace->code_backup[2]=((u8*)(faddr))[2];
                        current_ftrace->code_backup[3]=((u8*)(faddr))[3];
                }

                ((u8*)(faddr))[0] = INV_OPCODE;
                ((u8*)(faddr))[1] = INV_OPCODE;
                ((u8*)(faddr))[2] = INV_OPCODE;
                ((u8*)(faddr))[3] = INV_OPCODE;

                current_ftrace->capture_backtrace = 1;

                return 0;
        }
        else if(action == DISABLE_BACKTRACE){
                struct ftrace_info *current_ftrace = ctx->ft_md_base->next;
                while (current_ftrace) {
                        if (current_ftrace->faddr == faddr) {
                                break;
                        }
                        current_ftrace = current_ftrace->next;
                }
                if(current_ftrace == NULL){
                        return -EINVAL;
                }
                ((u8*)(faddr))[0] = current_ftrace->code_backup[0];
                ((u8*)(faddr))[1] = current_ftrace->code_backup[1];
                ((u8*)(faddr))[2] = current_ftrace->code_backup[2];
                ((u8*)(faddr))[3] = current_ftrace->code_backup[3];

                current_ftrace->capture_backtrace = 0;

                return 0;
        }

        return -EINVAL;
}

//Fault handler
long handle_ftrace_fault(struct user_regs *regs)
{
        struct exec_context *current = get_current_ctx();
        unsigned long faddr1 = regs->entry_rip;
        struct ftrace_info *current_ftrace = current->ft_md_base->next;
        while (current_ftrace) {
                if (current_ftrace->faddr == faddr1) {
                        break;
                }
                current_ftrace = current_ftrace->next;
        }
        if(current_ftrace == NULL){
                return -EINVAL;
        }
        struct file* trace_buff_file = current->files[current_ftrace->fd];
        u64 * func_info_buffer = (u64 *)os_page_alloc(USER_REG);
        func_info_buffer[0] = current_ftrace->num_args+1;
        func_info_buffer[1] = faddr1;
        if(current_ftrace->num_args == 1){
                func_info_buffer[2] = regs->rdi;
        }
        else if(current_ftrace->num_args == 2){
                func_info_buffer[2] = regs->rdi;
                func_info_buffer[3] = regs->rsi;
        }
        else if( current_ftrace->num_args == 3){
                func_info_buffer[2] = regs->rdi;
                func_info_buffer[3] = regs->rsi;
                func_info_buffer[4] = regs->rdx;
        }
        else if( current_ftrace->num_args == 4){
                func_info_buffer[2] = regs->rdi;
                func_info_buffer[3] = regs->rsi;
                func_info_buffer[4] = regs->rdx;
                func_info_buffer[5] = regs->rcx;
        }
        else if( current_ftrace->num_args == 5){
                func_info_buffer[2] = regs->rdi;
                func_info_buffer[3] = regs->rsi;
                func_info_buffer[4] = regs->rdx;
                func_info_buffer[5] = regs->rcx;
                func_info_buffer[6] = regs->r8;
        }
        
        // Checking backtrace
        if(current_ftrace->capture_backtrace == 1){
                int itr = current_ftrace->num_args + 2;
                func_info_buffer[itr++] = faddr1;
                func_info_buffer[0]++;
                if(*((u64*)regs->entry_rsp) != END_ADDR){
                        func_info_buffer[itr++] = *((u64*)regs->entry_rsp);
                        func_info_buffer[0]++;
                        u64 caller_rbp = regs->rbp;
                        while ( *((u64 *)(caller_rbp + 8)) != END_ADDR){
                                func_info_buffer[itr++] = *((u64 *)(caller_rbp + 8));
                                caller_rbp = *((u64 *)caller_rbp);
                                func_info_buffer[0]++;
                        }
                }
                else{
                        trace_buffer_write_aux(trace_buff_file, (char *)func_info_buffer, (func_info_buffer[0] +  1)*8);
                        os_page_free(USER_REG,func_info_buffer);
                        regs->entry_rsp -= 8;
                        *((u64*)regs->entry_rsp) = regs->rbp;
                        regs->rbp = regs->entry_rsp;
                        regs->entry_rip += 4;
                        return 0;
                }
        }
        trace_buffer_write_aux(trace_buff_file, (char *)func_info_buffer, (func_info_buffer[0] + 1)*8);
        os_page_free(USER_REG, func_info_buffer);
        // Execute first instruction
        regs->entry_rsp -= 8;
        *((u64*)regs->entry_rsp) = regs->rbp;
        regs->rbp = regs->entry_rsp;
        regs->entry_rip += 4;
        return 0;
}


int sys_read_ftrace(struct file *filep, char *buff, u64 count)
{
        u64 bytes_read = 0;
        u64* temp_buffer = (u64 *) os_page_alloc(USER_REG);
        for(u64 i = 0; (i < count) && ((filep->trace_buffer->read_offset != filep->trace_buffer->write_offset) || (filep->trace_buffer->read_offset == filep->trace_buffer->write_offset && filep->trace_buffer->is_full == 1)); i++){
                trace_buffer_read_aux(filep,(char *)temp_buffer, 8);
                u64 num_of_params=((u64 *)temp_buffer)[0];
                for(u64 j = 0; j < num_of_params; j++){
                        trace_buffer_read_aux(filep, buff, 8);
                        buff = buff + 8;
                        bytes_read+=8;
                }
                //free the temp buffer
                os_page_free(USER_REG,temp_buffer);
        }
        return bytes_read;
}
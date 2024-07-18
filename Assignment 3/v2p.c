#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/*
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables
 * */
#define _4KB 4096

/**
 * mprotect System call Implementation.
 */

void protect_vma_pfn(struct exec_context *current, u64 addr, int length, int prot)
{
    int pages = length/_4KB;
    for(int i = 0; i < pages; i++){
        u64* pgd_va = (u64 *)osmap(current->pgd);
        u64 pgd_offset = ((addr + _4KB*i) >>(12+9+9+9)) & 0x1FF;
        u64* pgd_entry_addr = (pgd_va + pgd_offset);
        u64 pgd_entry = *(pgd_entry_addr);

        u64* pud_va;
        if((pgd_entry & 1) == 1){
            // printk("pgd map\n");
            pud_va = (u64 *)osmap(pgd_entry>>12);
        }
        else{
            continue;
        }

        u64 pud_offset = ((addr + _4KB*i)>>(12+9+9)) & 0x1FF;
        u64* pud_entry_addr = (pud_va + pud_offset);
        u64 pud_entry = *(pud_entry_addr);

        u64* pmd_va;
        if((pud_entry & 1) == 1){
            pmd_va = (u64 *)osmap(pud_entry>>12);
        }
        else{
            continue;;
        }

        u64 pmd_offset = ((addr + _4KB*i)>>(12+9)) & 0x1FF;
        u64* pmd_entry_addr = (pmd_va + pmd_offset);
        u64 pmd_entry = *(pmd_entry_addr);
        
        u64* pte_va;
        if((pmd_entry & 1) == 1){
            pte_va = (u64 *)osmap(pmd_entry>>12);
        }
        else{
            continue;
        }

        u64 pte_offset = ((addr + _4KB*i)>>(12)) & 0x1FF;
        u64* pte_entry_addr = (pte_va + pte_offset);
        u64 pte_entry = *pte_entry_addr;
        // printk("pte_entry 1%x\n", pte_entry);
        if((pte_entry & 1) == 1){
            if(get_pfn_refcount(pte_entry >> 12) > 1){
                if(prot == PROT_READ){
                    *(pte_entry_addr) = *(pte_entry_addr) & (u64)(~(1 << 3));
                }
                asm volatile("invlpg (%0)"::"r" (addr + _4KB*i));
                return; // not sure
            }
            if (prot == PROT_READ){
                *(pte_entry_addr) = *(pte_entry_addr) & (u64)(~(1 << 3));
            }
            else if (prot == (PROT_READ | PROT_WRITE)){
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 3);
            }
            asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
            continue;
        }
        else{
            continue;
        }
    }
    
}

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if(length <= 0) return -1;
    // if(length >= 2^21) return -1;
    // if(current->vm_area) return 0;
    //making length of vma to be a multiple of 4KB
    long vma_length = (length%_4KB == 0) ? length : (length/_4KB + 1)*_4KB;
    struct vm_area * temp = current->vm_area;
    struct vm_area * temp_prev_1 = temp;
    int addr_on_block = -1;
    // printk("length to change: %d\n", vma_length);
    while(temp != NULL){
        if(temp->vm_end <= addr && addr < temp->vm_next->vm_start){
            addr_on_block = 0;
            break;
        }
        else if(temp->vm_start <= addr && addr < temp->vm_end){
            if(temp->vm_start == addr && addr + vma_length < temp->vm_end){
                if(temp->access_flags == prot){
                    return 0;
                }
                protect_vma_pfn(current,addr,vma_length,prot);
                struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_node->vm_start = addr + vma_length;
                new_node->vm_end = temp->vm_end;
                new_node->vm_next = temp->vm_next;
                new_node->access_flags = temp->access_flags;
                temp->vm_end = addr + vma_length;
                temp->access_flags = prot;
                temp->vm_next = new_node;
                // printk("start: %x\n", new_node->vm_start);
                stats->num_vm_area++;
                if(temp_prev_1 != temp && temp_prev_1->vm_end == temp->vm_start && temp_prev_1->access_flags == temp->access_flags){
                    temp_prev_1->vm_end = temp->vm_end;
                    temp_prev_1->vm_next = temp->vm_next;
                    os_free(temp,sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
                return 0;
            }
            else if(temp->vm_start < addr && addr + vma_length < temp->vm_end){
                if(stats->num_vm_area == 127){
                    return -EINVAL;
                }
                if(temp->access_flags == prot){
                    return 0;
                }
                protect_vma_pfn(current,addr,vma_length,prot);
                struct vm_area *new_node_end = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_node_end->vm_start = addr + vma_length;
                new_node_end->vm_end = temp->vm_end;
                new_node_end->vm_next = temp->vm_next;
                new_node_end->access_flags = temp->access_flags;
                struct vm_area *new_node_mid = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_node_mid->vm_start = addr;
                new_node_mid->vm_end = addr + vma_length;
                new_node_mid->vm_next = new_node_end;
                new_node_mid->access_flags = prot;

                temp->vm_end = addr;
                temp->vm_next = new_node_mid;
                // printk("start: %x\n", new_node->vm_start);
                stats->num_vm_area++;
                stats->num_vm_area++;
                return 0;
            }
            else if(temp->vm_start < addr && addr + vma_length == temp->vm_end){
                if(temp->access_flags == prot){
                    return 0;
                }
                protect_vma_pfn(current,addr,vma_length,prot);
                struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_node->vm_start = addr;
                new_node->vm_end = temp->vm_end;
                new_node->vm_next = temp->vm_next;
                new_node->access_flags = prot;
                temp->vm_end = addr;
                temp->vm_next = new_node;
                // printk("start: %x\n", new_node->vm_start);
                stats->num_vm_area++;
                if(temp->vm_end == temp->vm_next->vm_start && temp->access_flags == temp->vm_next->access_flags){
                    temp->vm_end = temp->vm_next->vm_end;
                    struct vm_area * ptr_to_be_deleted = temp->vm_next;
                    temp->vm_next = temp->vm_next->vm_next;
                    os_free(ptr_to_be_deleted,sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
                return 0;
            }
            else if(temp->vm_start == addr && addr + vma_length == temp->vm_end){
                temp->access_flags = prot;
                protect_vma_pfn(current,addr,vma_length,prot);
                if(temp_prev_1 != temp && temp_prev_1->vm_end == temp->vm_start && temp_prev_1->access_flags == temp->access_flags){
                    temp_prev_1->vm_end = temp->vm_end;
                    temp_prev_1->vm_next = temp->vm_next;
                    os_free(temp,sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
                else if(temp_prev_1 == temp && temp->access_flags == temp->vm_next->access_flags){
                    temp->vm_end = temp->vm_next->vm_end;
                    struct vm_area * ptr_to_be_deleted = temp->vm_next;
                    temp->vm_next = temp->vm_next->vm_next;
                    os_free(ptr_to_be_deleted,sizeof(struct vm_area));
                    stats->num_vm_area--;
                    return 0;
                }
                if(temp->vm_end == temp->vm_next->vm_start && temp->access_flags == temp->vm_next->access_flags){
                    temp->vm_end = temp->vm_next->vm_end;
                    struct vm_area * ptr_to_be_deleted = temp->vm_next;
                    temp->vm_next = temp->vm_next->vm_next;
                    os_free(ptr_to_be_deleted,sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
                return 0;
            }
            addr_on_block = 1;
            break;
        }
        temp_prev_1 = temp;
        temp = temp->vm_next;
    }
    // printk("is address on block: %d\n", addr_on_block);
    int end_addr_on_block = 0;
    struct vm_area * temp_end = temp;
    struct vm_area * temp_prev = NULL;
    // at the end
    if(addr_on_block == -1){
        // printk("nothing to change\n");
        return 0;
    }
    // in the middle
    else {
        while(temp_end != NULL){
            if(temp_end->vm_end < addr + vma_length && addr + vma_length <= temp_end->vm_next->vm_start){
                end_addr_on_block = 0;
                break;
            }
            else if(temp_end->vm_start < addr + vma_length && addr + vma_length <= temp_end->vm_end){
                end_addr_on_block = 1;
                break;
            }
            temp_prev = temp_end;
            temp_end = temp_end->vm_next;
        }
    }
    if(temp_end == NULL){
        temp_end = temp_prev;
    }
    // printk("is end address on block: %d\n", end_addr_on_block);
    // printk("start addr: %x, end addr: %x, temp: %x\n", addr, temp_end->vm_start, temp->vm_start);

    struct vm_area * temp_merge = temp->vm_next;
    struct vm_area * temp_prev_merge = temp;
    while(temp_merge->vm_next != temp_end){
        temp_merge->access_flags = prot;
        if(temp_merge->vm_end < temp_merge->vm_next->vm_start){
            temp_prev_merge = temp_merge;
            temp_merge = temp_merge->vm_next;
        }
        else if(temp_merge->vm_end == temp_merge->vm_next->vm_start){
            protect_vma_pfn(current,temp_merge->vm_end,temp_merge->vm_next->vm_end-temp_merge->vm_end,prot);
            struct vm_area * ptr_to_be_deleted = temp_merge->vm_next;
            temp_merge->vm_end = temp_merge->vm_next->vm_end;
            temp_merge->vm_next = temp_merge->vm_next->vm_next;
            os_free(ptr_to_be_deleted, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
    }
    // printk("temp_merge->start = %x\n", temp_merge->vm_start);
    if(addr_on_block == 1){
        if(temp->vm_start < addr && addr < temp->vm_end && temp->access_flags != prot){
            // printk("left cuts\n");
            protect_vma_pfn(current,addr,temp->vm_end-addr,prot);
            struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
            new_node->vm_start = addr;
            new_node->vm_end = temp->vm_end;
            new_node->vm_next = temp->vm_next;
            new_node->access_flags = prot;
            temp->vm_end = addr;
            temp->vm_next = new_node;
            // printk("start: %x\n", new_node->vm_start);
            stats->num_vm_area++;
        }
        if(temp->vm_next->vm_end == temp->vm_next->vm_next->vm_start){
            // printk("cut joins to right\n");
            if(temp->vm_next->vm_next == temp_merge) temp_merge = temp->vm_next;
            struct vm_area * ptr_to_be_deleted = temp->vm_next->vm_next;
            temp->vm_next->vm_end = temp->vm_next->vm_next->vm_end;
            temp->vm_next->vm_next = temp->vm_next->vm_next->vm_next;
            os_free(ptr_to_be_deleted, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
    }
    if(end_addr_on_block == 1){
        if(temp_end->vm_start < addr + vma_length && addr + vma_length < temp_end->vm_end && temp->access_flags != prot){
            protect_vma_pfn(current,temp->vm_start,addr + vma_length - temp_end->vm_start,prot);
            struct vm_area *new_node_end = (struct vm_area *)os_alloc(sizeof(struct vm_area));
            new_node_end->vm_start = addr + vma_length;
            new_node_end->vm_end = temp_end->vm_end;
            new_node_end->vm_next = temp_end->vm_next;
            new_node_end->access_flags = temp_end->access_flags;
            temp_end->vm_end = addr + vma_length;
            temp_end->vm_next = new_node_end;
            temp_end->access_flags = prot;
            // printk("start: %x\n", new_node->vm_start);
            stats->num_vm_area++;
        }
        if(temp_merge->vm_end == temp_merge->vm_next->vm_start && temp_merge->access_flags == temp_merge->vm_next->access_flags){
            struct vm_area * ptr_to_be_deleted = temp_merge->vm_next;
            temp_merge->vm_end = temp_merge->vm_next->vm_end;
            temp_merge->vm_next = temp_merge->vm_next->vm_next;
            os_free(ptr_to_be_deleted, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
    }

    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    if(stats->num_vm_area == 128) return -EINVAL;
    if(flags == MAP_FIXED && !addr) return -EINVAL;
    if(length <= 0) return -EINVAL;
    if(!(prot == PROT_READ || (prot == (PROT_READ | PROT_WRITE)))) return -EINVAL;
    if(!(flags == 0 || flags == MAP_FIXED)) return -EINVAL;
    if(length >= 2*1024*1024) return -1;
    if(0 < addr && addr < MMAP_AREA_START + _4KB) return -1;
    if(addr > MMAP_AREA_END) return -1;
    //making length of vma to be a multiple of 4KB
    long vma_length = (length%_4KB == 0) ? length : (length/_4KB + 1)*_4KB;
    // accessing head of vm_area
    struct vm_area * vm_area_head = current->vm_area;
    // if dummy node is not present, create a new dummy node
    // printk("HI2\n");
    if(vm_area_head == NULL){
        struct vm_area *dummy_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
        dummy_node->vm_start = MMAP_AREA_START;
        dummy_node->vm_end = MMAP_AREA_START + _4KB;
        dummy_node->vm_next = NULL;
        dummy_node->access_flags = 0;
        current->vm_area = dummy_node;
        stats->num_vm_area++;
    }
    // printk("length: %d\n", vma_length);
    // Take care of count of vma!!!!!
    // Take care of maximum vm areas!!!!!!!!!!

    // if address is NULL
    if(addr == 0){
        // printk("entered null\n");
        if(flags == MAP_FIXED){
            return -EINVAL;
        }
        struct vm_area * temp = current->vm_area;
        while(temp != NULL){
            // insert at end
            // printk("hehe\n");
            if(temp->vm_next == NULL){
                // diff protection
                if(temp->access_flags != prot){
                    struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                    new_node->vm_start = temp->vm_end;
                    new_node->vm_end = temp->vm_end + vma_length;
                    new_node->vm_next = NULL;
                    new_node->access_flags = prot;
                    temp->vm_next = new_node;
                    // printk("start: %x\n", new_node->vm_start);
                    stats->num_vm_area++;
                    return new_node->vm_start;
                }
                // same protection
                else{
                    temp->vm_end = temp->vm_end + vma_length;
                    // printk("start: %x", temp->vm_start);
                    return temp->vm_end-vma_length;
                }
            }
            // insert in middle
            if(temp->vm_next->vm_start >= temp->vm_end + vma_length){
                // left and right both are different
                if(temp->access_flags != prot && temp->vm_next->access_flags != prot){
                    struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                    new_node->vm_start = temp->vm_end;
                    new_node->vm_end = temp->vm_end + vma_length;
                    new_node->vm_next = temp->vm_next;
                    new_node->access_flags = prot;
                    temp->vm_next = new_node;
                    // printk("start: %x\n", new_node->vm_start);
                    stats->num_vm_area++;
                    return new_node->vm_start;
                }
                // left same
                else if(temp->access_flags == prot && temp->vm_next->access_flags != prot){
                    temp->vm_end = temp->vm_end + vma_length;
                    // printk("start: %x\n", temp->vm_start);
                    return temp->vm_end-vma_length;
                }
                // right same
                else if(temp->access_flags != prot && temp->vm_next->access_flags == prot){
                    if(temp->vm_next->vm_start > temp->vm_end + vma_length){
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = temp->vm_end;
                        new_node->vm_end = temp->vm_end + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return new_node->vm_start;
                    }
                    else{
                        temp->vm_next->vm_start = temp->vm_next->vm_start - vma_length;
                        // printk("start: %x\n", temp->vm_next->vm_start);
                        return temp->vm_next->vm_start;
                    }
                }
                // all same
                else if(temp->access_flags == prot && temp->vm_next->access_flags == prot){
                    if(temp->vm_next->vm_start == temp->vm_end + vma_length){
                        long ptr = temp->vm_end;
                        temp->vm_end = temp->vm_next->vm_end;
                        struct vm_area *ptr_to_be_deleted = temp->vm_next;
                        temp->vm_next = temp->vm_next->vm_next;
                        os_free(ptr_to_be_deleted, sizeof(struct vm_area));
                        stats->num_vm_area--;
                        return ptr;
                    }
                    else{
                        temp->vm_end = temp->vm_end + vma_length;
                        // printk("start: %x\n", temp->vm_start);
                        return temp->vm_end - vma_length;
                    }
                }
            }

            temp = temp->vm_next;
        }
    }

    else{
        // Hint of address
        if(flags == 0){
            struct vm_area * temp = current->vm_area;
            while(temp != NULL){
                // between two vm areas succesfully with spaces on each side
                if(temp->vm_end < addr && addr < temp->vm_next->vm_start - vma_length){
                    struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                    new_node->vm_start = addr;
                    new_node->vm_end = addr + vma_length;
                    new_node->vm_next = temp->vm_next;
                    new_node->access_flags = prot;
                    temp->vm_next = new_node;
                    // printk("start: %x\n", new_node->vm_start);
                    stats->num_vm_area++;
                    return addr;
                }
                // joined to left
                else if(temp->vm_end == addr && addr < temp->vm_next->vm_start - vma_length){
                    // merge with left
                    if(temp->access_flags == prot){
                        temp->vm_end = temp->vm_end + vma_length;
                        // printk("start: %x\n", temp->vm_start);
                        return addr;
                    }
                    // no merge
                    else{
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = addr;
                        new_node->vm_end = addr + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return addr;
                    }
                }
                //joined to right
                else if(temp->vm_end < addr && addr == temp->vm_next->vm_start - vma_length){
                    // merge with right
                    if(temp->vm_next->access_flags == prot){
                        temp->vm_next->vm_start = temp->vm_next->vm_start - vma_length;
                        // printk("start: %x\n", temp->vm_next->vm_start);
                        return addr;
                    }
                    // no merge
                    else{
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = addr;
                        new_node->vm_end = addr + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return new_node->vm_start;
                    }
                }
                // exactly between space
                else if(temp->vm_end == addr && addr == temp->vm_next->vm_start - vma_length){
                    if(temp->access_flags == prot && temp->vm_next->access_flags == prot){
                        temp->vm_end = temp->vm_next->vm_end;
                        struct vm_area *ptr_to_be_deleted = temp->vm_next;
                        temp->vm_next = temp->vm_next->vm_next;
                        os_free(ptr_to_be_deleted, sizeof(struct vm_area));
                        // printk("start: %x\n", temp->vm_start);
                        stats->num_vm_area--;
                        return addr;
                    }
                    else if(temp->access_flags != prot && temp->vm_next->access_flags != prot){
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = addr;
                        new_node->vm_end = addr + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return addr;
                    }
                    else if(temp->access_flags == prot && temp->vm_next->access_flags != prot){
                        temp->vm_end = temp->vm_end + vma_length;
                        // printk("start: %x\n", temp->vm_start);
                        return addr;
                    }
                    else if(temp->access_flags != prot && temp->vm_next->access_flags == prot){
                        temp->vm_next->vm_start = temp->vm_next->vm_start - vma_length;
                        // printk("start: %x\n", temp->vm_next->vm_start);
                        return addr;
                    }
                }
                else if(addr < temp->vm_start){
                    break;
                }
                temp = temp->vm_next;

            }
            // insertion at end
            if(addr > temp->vm_end && temp->vm_next == NULL ){
                struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_node->vm_start = addr;
                new_node->vm_end = addr + vma_length;
                new_node->vm_next = NULL;
                new_node->access_flags = prot;
                temp->vm_next = new_node;
                // printk("start: %x\n", new_node->vm_start);
                stats->num_vm_area++;
                return new_node->vm_start;
            }
            else if(addr == temp->vm_end && temp->vm_next == NULL){
                // diff protection
                if(temp->access_flags != prot){
                    struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                    new_node->vm_start = addr;
                    new_node->vm_end = addr + vma_length;
                    new_node->vm_next = NULL;
                    new_node->access_flags = prot;
                    temp->vm_next = new_node;
                    // printk("start: %x\n", new_node->vm_start);
                    stats->num_vm_area++;
                    return new_node->vm_start;
                }
                // same protection
                else{
                    temp->vm_end = temp->vm_end + vma_length;
                    // printk("start: %x\n", temp->vm_start);
                    return temp->vm_end - vma_length;
                }
            }
            temp = current->vm_area;
            while(temp != NULL){
            // insert at end
            // printk("hehe\n");
                if(temp->vm_next == NULL){
                    // diff protection
                    if(temp->access_flags != prot){
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = temp->vm_end;
                        new_node->vm_end = temp->vm_end + vma_length;
                        new_node->vm_next = NULL;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return new_node->vm_start;
                    }
                    // same protection
                    else{
                        temp->vm_end = temp->vm_end + vma_length;
                        // printk("start: %x", temp->vm_start);
                        return temp->vm_end-vma_length;
                    }
                }
                // insert in middle
                if(temp->vm_next->vm_start >= temp->vm_end + vma_length){
                    // left and right both are different
                    if(temp->access_flags != prot && temp->vm_next->access_flags != prot){
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = temp->vm_end;
                        new_node->vm_end = temp->vm_end + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return new_node->vm_start;
                    }
                    // left same
                    else if(temp->access_flags == prot && temp->vm_next->access_flags != prot){
                        temp->vm_end = temp->vm_end + vma_length;
                        // printk("start: %x\n", temp->vm_start);
                        return temp->vm_end-vma_length;
                    }
                    // right same
                    else if(temp->access_flags != prot && temp->vm_next->access_flags == prot){
                        if(temp->vm_next->vm_start > temp->vm_end + vma_length){
                            struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                            new_node->vm_start = temp->vm_end;
                            new_node->vm_end = temp->vm_end + vma_length;
                            new_node->vm_next = temp->vm_next;
                            new_node->access_flags = prot;
                            temp->vm_next = new_node;
                            // printk("start: %x\n", new_node->vm_start);
                            stats->num_vm_area++;
                            return new_node->vm_start;
                        }
                        else{
                            temp->vm_next->vm_start = temp->vm_next->vm_start - vma_length;
                            // printk("start: %x\n", temp->vm_next->vm_start);
                            return temp->vm_next->vm_start;
                        }
                    }
                    // all same
                    else if(temp->access_flags == prot && temp->vm_next->access_flags == prot){
                        if(temp->vm_next->vm_start == temp->vm_end + vma_length){
                            long ptr = temp->vm_end;
                            temp->vm_end = temp->vm_next->vm_end;
                            struct vm_area *ptr_to_be_deleted = temp->vm_next;
                            temp->vm_next = temp->vm_next->vm_next;
                            os_free(ptr_to_be_deleted, sizeof(struct vm_area));
                            stats->num_vm_area--;
                            return ptr;
                        }
                        else{
                            temp->vm_end = temp->vm_end + vma_length;
                            // printk("start: %x\n", temp->vm_start);
                            return temp->vm_end - vma_length;
                        }
                    }
                }

                temp = temp->vm_next;
            }
        }
        // Rigid address
        else if (flags == MAP_FIXED){
            struct vm_area * temp = current->vm_area;
            while(temp != NULL){
                // between two vm areas succesfully with spaces on each side
                if(temp->vm_end < addr && addr < temp->vm_next->vm_start - vma_length){
                    struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                    new_node->vm_start = addr;
                    new_node->vm_end = addr + vma_length;
                    new_node->vm_next = temp->vm_next;
                    new_node->access_flags = prot;
                    temp->vm_next = new_node;
                    // printk("start: %x\n", new_node->vm_start);
                    stats->num_vm_area++;
                    return addr;
                }
                // joined to left
                else if(temp->vm_end == addr && addr < temp->vm_next->vm_start - vma_length){
                    // merge with left
                    if(temp->access_flags == prot){
                        temp->vm_end = temp->vm_end + vma_length;
                        // printk("start: %x\n", temp->vm_start);
                        return addr;
                    }
                    // no merge
                    else{
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = addr;
                        new_node->vm_end = addr + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return addr;
                    }
                }
                //joined to right
                else if(temp->vm_end < addr && addr == temp->vm_next->vm_start - vma_length){
                    // merge with right
                    if(temp->vm_next->access_flags == prot){
                        temp->vm_next->vm_start = temp->vm_next->vm_start - vma_length;
                        printk("start: %x\n", temp->vm_next->vm_start);
                        return addr;
                    }
                    // no merge
                    else{
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = addr;
                        new_node->vm_end = addr + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return addr;
                    }
                }
                // exactly between space
                else if(temp->vm_end == addr && addr == temp->vm_next->vm_start - vma_length){
                    if(temp->access_flags == prot && temp->vm_next->access_flags == prot){
                        temp->vm_end = temp->vm_next->vm_end;
                        struct vm_area *ptr_to_be_deleted = temp->vm_next;
                        temp->vm_next = temp->vm_next->vm_next;
                        os_free(ptr_to_be_deleted, sizeof(struct vm_area));
                        // printk("start: %x\n", temp->vm_start);
                        return addr;
                    }
                    else if(temp->access_flags != prot && temp->vm_next->access_flags != prot){
                        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                        new_node->vm_start = addr;
                        new_node->vm_end = addr + vma_length;
                        new_node->vm_next = temp->vm_next;
                        new_node->access_flags = prot;
                        temp->vm_next = new_node;
                        // printk("start: %x\n", new_node->vm_start);
                        stats->num_vm_area++;
                        return addr;
                    }
                    else if(temp->access_flags == prot && temp->vm_next->access_flags != prot){
                        temp->vm_end = temp->vm_end + vma_length;
                        // printk("start: %x\n", temp->vm_start);
                        return addr;
                    }
                    else if(temp->access_flags != prot && temp->vm_next->access_flags == prot){
                        temp->vm_next->vm_start = temp->vm_next->vm_start - vma_length;
                        // printk("start: %x\n", temp->vm_next->vm_start);
                        return addr;
                    }
                }
                else if(addr < temp->vm_start){
                    break;
                }
                temp = temp->vm_next;
            }
            // insertion at end
            if(addr > temp->vm_end && temp->vm_next == NULL ){
                struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_node->vm_start = addr;
                new_node->vm_end = addr + vma_length;
                new_node->vm_next = NULL;
                new_node->access_flags = prot;
                temp->vm_next = new_node;
                // printk("start: %x\n", new_node->vm_start);
                stats->num_vm_area++;
                return addr;
            }
            else if(addr == temp->vm_end && temp->vm_next == NULL){
                // diff protection
                if(temp->access_flags != prot){
                    struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                    new_node->vm_start = addr;
                    new_node->vm_end = addr + vma_length;
                    new_node->vm_next = NULL;
                    new_node->access_flags = prot;
                    temp->vm_next = new_node;
                    // printk("start: %x\n", new_node->vm_start);
                    stats->num_vm_area++;
                    return addr;
                }
                // same protection
                else{
                    temp->vm_end = temp->vm_end + vma_length;
                    // printk("start: %x\n", temp->vm_start);
                    return addr;
                }
            }
            return -EINVAL;
        }
    }
    return -EINVAL;
}

/**
 * munmap system call implemenations
 */

void free_vma_pfn(struct exec_context *current, u64 addr, int length)
{
    int pages = length/_4KB;
    for(int i = 0; i < pages; i++){
        u64* pgd_va = (u64 *)osmap(current->pgd);
        u64 pgd_offset = ((addr + _4KB*i) >>(12+9+9+9)) & 0x1FF;
        u64* pgd_entry_addr = (pgd_va + pgd_offset);
        u64 pgd_entry = *(pgd_entry_addr);

        u64* pud_va;
        if((pgd_entry & 1) == 1){
            // printk("pgd map\n");
            pud_va = (u64 *)osmap(pgd_entry>>12);
        }
        else{
            continue;
        }

        u64 pud_offset = ((addr + _4KB*i)>>(12+9+9)) & 0x1FF;
        u64* pud_entry_addr = (pud_va + pud_offset);
        u64 pud_entry = *(pud_entry_addr);

        u64* pmd_va;
        if((pud_entry & 1) == 1){
            pmd_va = (u64 *)osmap(pud_entry>>12);
        }
        else{
            continue;;
        }

        u64 pmd_offset = ((addr + _4KB*i)>>(12+9)) & 0x1FF;
        u64* pmd_entry_addr = (pmd_va + pmd_offset);
        u64 pmd_entry = *(pmd_entry_addr);
        
        u64* pte_va;
        if((pmd_entry & 1) == 1){
            pte_va = (u64 *)osmap(pmd_entry>>12);
        }
        else{
            continue;
        }

        u64 pte_offset = ((addr + _4KB*i)>>(12)) & 0x1FF;
        u64* pte_entry_addr = (pte_va + pte_offset);
        u64 pte_entry = *pte_entry_addr;
        // printk("pte_entry 1%x\n", pte_entry);
        if((pte_entry & 1) == 1){
            if(get_pfn_refcount(pte_entry >> 12) == 1){
                put_pfn(pte_entry >> 12);
                os_pfn_free(USER_REG, (u64)((pte_entry >> 12)));
                *(pte_entry_addr) = 0;
            }
            else{
                *(pte_entry_addr) = 0;
            }
            asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
            continue;
        }
        else{
            continue;
        }
    }
    
}

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if(length <= 0) return -1;
    // if(current->vm_area) return 0;
    //making length of vma to be a multiple of 4KB
    long vma_length = (length%_4KB == 0) ? length : (length/_4KB + 1)*_4KB;
    struct vm_area * temp = current->vm_area;
    int addr_on_block = -1;
    // printk("length to delete: %d\n", vma_length);
    while(temp != NULL){

        if(temp->vm_end <= addr && addr < temp->vm_next->vm_start){
            addr_on_block = 0;
            break;
        }
        else if(temp->vm_start <= addr && addr < temp->vm_end){
            if(temp->vm_start == addr && addr + vma_length < temp->vm_end){
                free_vma_pfn(current,temp->vm_start,vma_length);
                temp->vm_start = addr + vma_length;
                return 0;
            }
            else if(temp->vm_start < addr && addr + vma_length < temp->vm_end){
                if(stats->num_vm_area == 128){
                    return -EINVAL;
                }
                free_vma_pfn(current,addr,vma_length);
                struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_node->vm_start = addr + vma_length;
                new_node->vm_end = temp->vm_end;
                new_node->vm_next = temp->vm_next;
                new_node->access_flags = temp->access_flags;
                temp->vm_end = addr;
                temp->vm_next = new_node;
                // printk("start: %x\n", new_node->vm_start);
                stats->num_vm_area++;
                return 0;
            }
            else if(temp->vm_start < addr && addr + vma_length == temp->vm_end){
                free_vma_pfn(current,addr,vma_length);
                temp->vm_end = addr;
                return 0;
            }
            else if(temp->vm_start == addr && addr + vma_length == temp->vm_end){
                struct vm_area * temp_new = current->vm_area;
                while(temp_new->vm_next != temp){
                    temp_new = temp_new->vm_next;
                }
                temp_new->vm_next = temp->vm_next;
                free_vma_pfn(current,addr,vma_length);
                os_free(temp, sizeof(struct vm_area));
                stats->num_vm_area--;
                return 0;
            }
            addr_on_block = 1;
            break;
        }
        temp = temp->vm_next;
    }
    // printk("is address on block: %d\n", addr_on_block);
    int end_addr_on_block = 0;
    long address_end_of_length = 0;
    struct vm_area * temp_end = temp;
    struct vm_area * temp_prev = NULL;
    // at the end
    if(addr_on_block == -1){
        // printk("nothing to delete\n");
        return 0;
    }
    // in the middle
    else {
        while(temp_end != NULL){
            if(temp_end->vm_end < addr + vma_length && addr + vma_length <= temp_end->vm_next->vm_start){
                end_addr_on_block = 0;
                address_end_of_length = temp_end->vm_next->vm_start;
                break;
            }
            else if(temp_end->vm_start < addr + vma_length && addr + vma_length <= temp_end->vm_end){
                end_addr_on_block = 1;
                address_end_of_length = addr + vma_length;
                break;
            }
            temp_prev = temp_end;
            temp_end = temp_end->vm_next;
        }
    }
    if(temp_end == NULL){
        temp_end = temp_prev;
    }
    // printk("is end address on block: %d\n", end_addr_on_block);
    // printk("start addr: %x, end addr: %x, temp: %x\n", addr, temp_end->vm_start, temp->vm_start);
    // now the start and end address is available
    struct vm_area * temp_new = current->vm_area;
    if(addr_on_block == 1){
        free_vma_pfn(current,addr,temp->vm_end - addr);
        temp->vm_end = addr;
        if(temp->vm_start == temp->vm_end){
            while(temp_new->vm_next != temp){
                temp_new = temp_new->vm_next;
            }
            temp_new->vm_next = temp->vm_next;
            os_free(temp, sizeof(struct vm_area));
            stats->num_vm_area--;
            temp = temp_new->vm_next;
        }
    }
    struct vm_area * del_temp = temp_end->vm_next;
    // printk("deletion of intermediate guys started\n");
    // printk("start addr: %x, end addr: %x, temp: %x\n", addr, temp_end->vm_start, temp->vm_start);
    while(temp->vm_next != del_temp && temp->vm_start <= temp_end->vm_start){
        // printk("hi\n");
        if(addr + vma_length >= temp->vm_next->vm_end){
            struct vm_area * ptr_to_be_deleted = temp->vm_next;
            temp->vm_next = temp->vm_next->vm_next;
            free_vma_pfn(current,temp->vm_start,temp->vm_end - temp->vm_start);
            os_free(ptr_to_be_deleted, sizeof(struct vm_area));
            stats->num_vm_area--;
            // printk("deleted one node\n");
        }
        else if(temp->vm_next->vm_start < addr + vma_length && addr + vma_length < temp->vm_next->vm_end){
            free_vma_pfn(current,temp->vm_start,addr +vma_length - temp->vm_start);
            temp->vm_next->vm_start = addr + vma_length;
            return 0;
        }
        // temp = temp->vm_next;
    }
    return 0;
}

/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    if(0 < addr && addr < MMAP_AREA_START + _4KB) return -1;
    if(addr > MMAP_AREA_END) return -1;
    // printk("entered pfh with error code : %x\n", error_code);
    struct vm_area * temp = current->vm_area;
    int addr_on_block = -1;
    while(temp != NULL){

        if(temp->vm_end <= addr && addr < temp->vm_next->vm_start){
            addr_on_block = 0;
            return -1;
        }
        else if(temp->vm_start <= addr && addr < temp->vm_end){
            addr_on_block = 1;
            break;
        }
        temp = temp->vm_next;
    }
    // printk("temp->vm_start : %x\n", temp->vm_start);
    // at the end
    if(addr_on_block == -1){
        return -1;
    }
    if((error_code == 6 || error_code == 7) && temp->access_flags == PROT_READ){
        return -1;
    }
    if (error_code == 7 && temp->access_flags == (PROT_READ | PROT_WRITE))
    {
        handle_cow_fault(current, addr, temp->access_flags);
        return 1;
    }

    // printk("reached here\n");
    u64* pgd_va = (u64 *)osmap(current->pgd);
    u64 pgd_offset = (addr>>(12+9+9+9)) & 0x1FF;
    u64* pgd_entry_addr = (pgd_va + pgd_offset);
    u64 pgd_entry = *(pgd_entry_addr);

    u64* pud_va;
    if((pgd_entry & 1) == 1){
        // printk("pgd map\n");
        pud_va = (u64 *)osmap(pgd_entry>>12);
    }
    else{
        // printk("pgd map alloc\n");
        u32 new_pfn = os_pfn_alloc(OS_PT_REG);
        *(pgd_entry_addr) = (new_pfn<<12) | (25);
        pgd_entry = *(pgd_entry_addr);
        asm volatile("invlpg (%0)"::"r" (addr));
        pud_va = (u64 *)osmap(new_pfn);
    }

    u64 pud_offset = (addr>>(12+9+9)) & 0x1FF;
    u64* pud_entry_addr = (pud_va + pud_offset);
    u64 pud_entry = *(pud_entry_addr);

    u64* pmd_va;
    if((pud_entry & 1) == 1){
        // printk("pud map\n");
        pmd_va = (u64 *)osmap(pud_entry>>12);
    }
    else{
        // printk("pud map alloc %x\n", pud_entry);
        u32 new_pfn = os_pfn_alloc(OS_PT_REG);
        *(pud_entry_addr) = (new_pfn<<12) | (25);
        pud_entry = *(pud_entry_addr);
        asm volatile("invlpg (%0)"::"r" (addr));
        pmd_va = (u64 *)osmap(new_pfn);
        // printk("here now\n");
    }

    u64 pmd_offset = (addr>>(12+9)) & 0x1FF;
    u64* pmd_entry_addr = (pmd_va + pmd_offset);
    u64 pmd_entry = *(pmd_entry_addr);
    // printk("here\n");
    u64* pte_va;
    if((pmd_entry & 1) == 1){
        // printk("pmd map\n");
        pte_va = (u64 *)osmap(pmd_entry>>12);
    }
    else{
        // printk("pmd map alloc\n");
        u32 new_pfn = os_pfn_alloc(OS_PT_REG);
        *(pmd_entry_addr) = (new_pfn<<12) | (25);
        pmd_entry = *(pmd_entry_addr);
        asm volatile("invlpg (%0)"::"r" (addr));
        pte_va = (u64 *)osmap(new_pfn);
    }

    u64 pte_offset = (addr>>(12)) & 0x1FF;
    u64* pte_entry_addr = (pte_va + pte_offset);
    u64 pte_entry = *pte_entry_addr;
    // printk("pte_entry 1%x\n", pte_entry);
    if((pte_entry & 1) == 0){
        // printk("pte map alloc\n");
        u32 new_pfn = os_pfn_alloc(USER_REG);
        *(pte_entry_addr) = (new_pfn<<12) | (0x11) | ((error_code & 2) << 2);
        pte_entry = *(pte_entry_addr);
        // printk("pte_entry %x\n", pte_entry);
        asm volatile("invlpg (%0)"::"r" (addr));
    }
    // printk("exited\n");
    return 1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the
 * end of this function (e.g., setup_child_context etc.)
 */

void copy_page_to_child(struct exec_context *parent, struct exec_context * child, u64 addr, int length){
    int pages = length/_4KB;
    for(int i = 0; i < pages; i++){
        u64* pgd_va_p = (u64 *)osmap(parent->pgd);
        u64* pgd_va_c = (u64 *)osmap(child->pgd);
        u64 pgd_offset = ((addr + _4KB*i) >>(12+9+9+9)) & 0x1FF;
        u64* pgd_entry_addr_p = (pgd_va_p + pgd_offset);
        u64* pgd_entry_addr_c = (pgd_va_c + pgd_offset);
        u64 pgd_entry_p = *(pgd_entry_addr_p);
        u64 pgd_entry_c = *(pgd_entry_addr_c);

        u64* pud_va_p;
        u64* pud_va_c;
        if((pgd_entry_p & 1) == 1){
            pud_va_p = (u64 *)osmap(pgd_entry_p>>12);
            if(pgd_entry_c & 1 == 1){
                *(pgd_entry_addr_c) = *(pgd_entry_addr_c) | (1 << 3) | (1 << 0) | (1 << 4);
                asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
                pud_va_c = osmap(pgd_entry_c >> 12);
            }
            else{
                u32 new_pfn = os_pfn_alloc(OS_PT_REG);
                *(pgd_entry_addr_c) = (new_pfn << 12) | (1 << 3) | (1 << 0) | (1 << 4);
                asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
                pud_va_c = osmap(new_pfn);
            }
        }
        else{
            *(pgd_entry_addr_c) = *(pgd_entry_addr_c) & (~(1 << 0));
            asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
            continue;
        }

        u64 pud_offset = ((addr + _4KB*i)>>(12+9+9)) & 0x1FF;
        u64* pud_entry_addr_p = (pud_va_p + pud_offset);
        u64* pud_entry_addr_c = (pud_va_c + pud_offset);
        u64 pud_entry_p = *(pud_entry_addr_p);
        u64 pud_entry_c = *(pud_entry_addr_c);

        u64* pmd_va_p;
        u64* pmd_va_c;
        if((pud_entry_p & 1) == 1){
            pmd_va_p = (u64 *)osmap(pud_entry_p>>12);
            if(pud_entry_c & 1 == 1){
                *(pud_entry_addr_c) = *(pud_entry_addr_c) | (1 << 3) | (1 << 0) | (1 << 4);
                asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
                pmd_va_c = osmap(pud_entry_c >> 12);
            }
            else{
                u32 new_pfn = os_pfn_alloc(OS_PT_REG);
                *(pud_entry_addr_c) = (new_pfn << 12) | (1 << 3) | (1 << 0) | (1 << 4);
                asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
                pmd_va_c = osmap(new_pfn);
            }
        }
        else{
            *(pud_entry_addr_c) = *(pud_entry_addr_c) & (~(1 << 0));
            asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
            continue;
        }

        u64 pmd_offset = ((addr + _4KB*i)>>(12+9)) & 0x1FF;
        u64* pmd_entry_addr_p = (pmd_va_p + pmd_offset);
        u64* pmd_entry_addr_c = (pmd_va_c + pmd_offset);
        u64 pmd_entry_p = *(pmd_entry_addr_p);
        u64 pmd_entry_c = *(pmd_entry_addr_c);
        
        u64* pte_va_p;
        u64* pte_va_c;
        if((pmd_entry_p & 1) == 1){
            pte_va_p = (u64 *)osmap(pmd_entry_p>>12);
            if(pmd_entry_c & 1 == 1){
                *(pmd_entry_addr_c) = *(pmd_entry_addr_c) | (1 << 3) | (1 << 0) | (1 << 4);
                asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
                pte_va_c = osmap(pmd_entry_c >> 12);
            }
            else{
                u32 new_pfn = os_pfn_alloc(OS_PT_REG);
                *(pmd_entry_addr_c) = (new_pfn << 12) | (1 << 3) | (1 << 0) | (1 << 4);
                asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
                pte_va_c = osmap(new_pfn);
            }
        }
        else{
            *(pmd_entry_addr_c) = *(pmd_entry_addr_c) & (~(1 << 0));
            asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
            continue;
        }

        u64 pte_offset = ((addr + _4KB*i)>>(12)) & 0x1FF;
        u64* pte_entry_addr_p = (pte_va_p + pte_offset);
        u64* pte_entry_addr_c = (pte_va_c + pte_offset);
        u64 pte_entry_p = *(pte_entry_addr_p);
        u64 pte_entry_c = *(pte_entry_addr_c);
        // printk("pte_entry 1%x\n", pte_entry);
        if((pte_entry_p & 1) == 1){
            *(pte_entry_addr_p) = *(pte_entry_addr_p) & (~(1 << 3));
            *(pte_entry_addr_p) = *(pte_entry_addr_p) | (1 << 0) | (1 << 4);
            *(pte_entry_addr_c) = *(pte_entry_addr_p);
            get_pfn(pte_entry_p >> 12);
            asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
            // continue;
        }
        else{
            *(pte_entry_addr_c) = *(pte_entry_addr_c) & (~(1 << 0));
            asm volatile("invlpg (%0)"::"r" ((addr + _4KB*i)));
            continue;
        }
    }
}

long do_cfork(){
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
     /* Do not modify above lines
     *
     * */
     /*--------------------- Your code [start]---------------*/

    pid = new_ctx->pid;
    new_ctx->ppid = ctx->pid;
    new_ctx->os_stack_pfn = ctx->os_stack_pfn;
    new_ctx->os_rsp = ctx->os_rsp;
    new_ctx->type = ctx->type;
    new_ctx->state = ctx->state;
    new_ctx->used_mem = ctx->used_mem;
    new_ctx->regs = ctx->regs;
    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;
    new_ctx->alarm_config_time = ctx->alarm_config_time;
    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;
    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
    new_ctx->ctx_threads = ctx->ctx_threads;

    for(int i = 0; i < MAX_SIGNALS; i++){
        new_ctx->sighandlers[i] = ctx->sighandlers[i];
    }

    for(int i = 0; i < MAX_MM_SEGS; i++){
        new_ctx->mms[i] = ctx->mms[i];
    }

    for(int i = 0; i < MAX_OPEN_FILES; i++){
        new_ctx->files[i] = ctx->files[i];
    }

    for(int i = 0; i < CNAME_MAX; i++){
        new_ctx->name[i] = ctx->name[i];
    }

    struct vm_area *head_p = ctx->vm_area;
    struct vm_area *temp_p = head_p;
    new_ctx->vm_area = NULL;
    if(head_p != NULL){
        struct vm_area *dummy_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
        dummy_node->vm_start = MMAP_AREA_START;
        dummy_node->vm_end = MMAP_AREA_START + _4KB;
        dummy_node->vm_next = NULL;
        dummy_node->access_flags = 0;
        new_ctx->vm_area = dummy_node;
        // stats->num_vm_area++;

        struct vm_area * temp_c = new_ctx->vm_area;
        while(temp_p != NULL){
            struct vm_area *new_node_c = (struct vm_area *)os_alloc(sizeof(struct vm_area));
            new_node_c->vm_start = temp_p->vm_start;
            new_node_c->vm_end = temp_p->vm_end;
            new_node_c->access_flags = temp_p->access_flags;
            temp_c->vm_next = new_node_c;
            temp_c = new_node_c;
            temp_p = temp_p->vm_next;

        }
        temp_c->vm_next = NULL;

        new_ctx->pgd = os_pfn_alloc(OS_PT_REG);
        if(new_ctx->pgd == 0){
            return -1;
        }

        temp_p = ctx->vm_area->vm_next;
        while (temp_p != NULL){
            copy_page_to_child(ctx,new_ctx,temp_p->vm_start,temp_p->vm_end - temp_p->vm_start);
            temp_p = temp_p->vm_next;
        } 
    }
    else{
        new_ctx->pgd = os_pfn_alloc(OS_PT_REG);
        if(new_ctx->pgd == 0){
            return -1;
        }
    }

    
    for(int i = 0; i < 3; i++){
        u64 current_mms_addr = ctx->mms[i].start;
        copy_page_to_child(ctx,new_ctx,current_mms_addr, ctx->mms[i].next_free - current_mms_addr);
    }
    u64 last_mms_addr = ctx->mms[3].start;
    copy_page_to_child(ctx,new_ctx,last_mms_addr, ctx->mms[3].end - last_mms_addr);
    

     /*--------------------- Your code [end] ----------------*/

     /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data)
 * it is called when there is a CoW violation in these areas.
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    u64* pgd_va = (u64 *)osmap(current->pgd);
    u64 pgd_offset = (vaddr>>(12+9+9+9)) & 0x1FF;
    u64* pgd_entry_addr = (pgd_va + pgd_offset);
    u64 pgd_entry = *(pgd_entry_addr);

    u64* pud_va;
    if((pgd_entry & 1) == 1){
        // printk("pgd map\n");
        pud_va = (u64 *)osmap(pgd_entry>>12);
    }
    else{
        return -1;
    }

    u64 pud_offset = (vaddr>>(12+9+9)) & 0x1FF;
    u64* pud_entry_addr = (pud_va + pud_offset);
    u64 pud_entry = *(pud_entry_addr);

    u64* pmd_va;
    if((pud_entry & 1) == 1){
        pmd_va = (u64 *)osmap(pud_entry>>12);
    }
    else{
        return -1;
    }

    u64 pmd_offset = (vaddr>>(12+9)) & 0x1FF;
    u64* pmd_entry_addr = (pmd_va + pmd_offset);
    u64 pmd_entry = *(pmd_entry_addr);
    // printk("here\n");
    u64* pte_va;
    if((pmd_entry & 1) == 1){
        // printk("pmd map\n");
        pte_va = (u64 *)osmap(pmd_entry>>12);
    }
    else{
        return -1;
    }

    u64 pte_offset = (vaddr>>(12)) & 0x1FF;
    u64* pte_entry_addr = (pte_va + pte_offset);
    u64 pte_entry = *pte_entry_addr;
    // printk("pte_entry 1%x\n", pte_entry);
    if((pte_entry & 1) == 1){
        int ref_count = get_pfn_refcount((pte_entry >> 12));
        if(ref_count > 1){
            // printk("refcount>1\n");
            u32 new_pfn = os_pfn_alloc(USER_REG);
            if(new_pfn == 0) return -1;
            put_pfn((pte_entry >> 12));
            memcpy((char*)osmap(new_pfn), (char*)osmap((pte_entry >> 12)), _4KB);
            *(pte_entry_addr) = (new_pfn << 12) | (*(pte_entry_addr) & 0xFFF);
            if(access_flags == (PROT_READ | PROT_WRITE)){
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 3) | (1 << 4) | (1 << 0);
            }
            else{
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 4) | (1 << 0);
            }
            asm volatile("invlpg (%0)"::"r" (vaddr));
        }
        else{
            if(access_flags == (PROT_READ | PROT_WRITE)){
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 3) | (1 << 4) | (1 << 0);
            }
            else{
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 4) | (1 << 0);
            }
            asm volatile("invlpg (%0)"::"r" (vaddr));
        }
    }
    else{
        return -1;
    }
    return 1;
}

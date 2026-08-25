use x86_64::{
    VirtAddr,
    instructions::segmentation::{self, Segment},
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable},
        paging::PhysFrame,
    },
};

pub fn create_and_load(frame: PhysFrame) {
    let phys_addr = frame.start_address();
    log::info!("Creating GDT at {:?}", phys_addr);
    let virt_addr = VirtAddr::new(phys_addr.as_u64()); // utilize identity mapping

    let ptr: *mut GlobalDescriptorTable = virt_addr.as_mut_ptr();

    let mut gdt = GlobalDescriptorTable::new();
    let code_selector = gdt.append(Descriptor::kernel_code_segment());
    let data_selector = gdt.append(Descriptor::kernel_data_segment());
    let gdt = unsafe {
        ptr.write(gdt);
        &*ptr
    };

    gdt.load();
    unsafe {
        segmentation::CS::set_reg(code_selector);
        segmentation::DS::set_reg(data_selector);
        segmentation::ES::set_reg(data_selector);
        segmentation::SS::set_reg(data_selector);
    }
}

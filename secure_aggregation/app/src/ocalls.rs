use std::slice;
use sgx_types::*;

#[no_mangle]
pub extern "C" fn ocall_load_next_data(
    encrypted_parameters_data_ptr: *const u8,  // 加密参数数据的指针
    encrypted_parameters_data: *mut u8,        // 加密参数数据的指针
    encrypted_parameters_size: usize,          // 加密参数数据的大小
    offset: usize,                              // 偏移量
) -> sgx_status_t {
    // 创建一个可变的 u8 类型的切片，用于存储要上传到 enclave 的加密参数数据
    let encrypted_parameters_to_upload_to_enclave: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(encrypted_parameters_data, encrypted_parameters_size) };

    unsafe {
        // 从给定偏移量开始，创建一个原始指针指向的 u8 类型切片，表示要复制到 enclave 的加密参数数据
        let encrypted_parameters = slice::from_raw_parts(
            encrypted_parameters_data_ptr.offset(offset as isize),
            encrypted_parameters_size
        );
        // 将加密参数数据复制到 enclave
        encrypted_parameters_to_upload_to_enclave.copy_from_slice(encrypted_parameters);
    }
    sgx_status_t::SGX_SUCCESS
}

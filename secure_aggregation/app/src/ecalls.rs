// 定义了一些与 SGX 相关的函数和数据结构，
// 并提供了一个函数 init_enclave 用于初始化 SGX enclave。
use sgx_types::*;
use sgx_urts::SgxEnclave;

// enclave.signed.so 文件是一个SGX的enclave部分的编译结果。
// 该文件是已签名的 enclave 二进制文件。在SGX中，enclave需要通过签名来确保其完整性和真实性。
// 签名由相应的私钥生成，并可以通过相应的公钥进行验证。这样可以确保 enclave 文件未被篡改，并且确保它来自可信的来源。
// 文件包含 enclave 的机器代码和相关元数据，以及签名信息。在运行 SGX 应用程序时，SGX 运行时会验证 enclave 文件的签名，以确保其有效性。
// 如果验证通过，SGX 运行时将加载 enclave 并启动其执行，从而创建安全执行环境。
static ENCLAVE_FILE: &'static str = "bin/enclave.signed.so";

extern "C" {
    pub fn ecall_fl_init(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        fl_id: u32,
        client_ids: *const u32,
        client_size: usize,
        sigma: f32,
        clipping: f32,
        sampling_ratio: f32,
        aggregation_alg: u32,
        verbose: u8,
        dp: u8,
    ) -> sgx_status_t;

    pub fn ecall_start_round(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        fl_id: u32,
        round: u32,
        sample_size: usize,
        sampled_client_ids: *mut u32,
    ) -> sgx_status_t;

    pub fn ecall_secure_aggregation(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        fl_id: u32,
        round: u32,
        client_ids: *const u32,
        client_size: usize,
        encrypted_parameters_data: *const u8,
        encrypted_parameters_size: usize,
        num_of_parameters: usize,
        num_of_sparse_parameters: usize,
        aggregation_alg: u32,
        updated_parameters_data: *mut f32,
        execution_time_results: *mut f32,
    ) -> sgx_status_t;

    pub fn ecall_client_size_optimized_secure_aggregation(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        fl_id: u32,
        round: u32,
        optimal_num_of_clients: usize,
        client_ids: *const u32,
        client_size: usize,
        encrypted_parameters_data_ptr: *const u8,
        num_of_parameters: usize,
        num_of_sparse_parameters: usize,
        aggregation_alg: u32,
        updated_parameters_data: *mut f32,
        execution_time_results: *mut f32,
    ) -> sgx_status_t;
}

// 初始化 enclave 实例
pub fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // 调用 sgx_create_enclave 初始化 enclave 实例
    // Debug Support: 将第二个参数设置为 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

// 一个Rust程序，它使用了一些外部的crate（库）和模块来实现安全聚合（secure aggregation）的功能

// 引入所需的外部crate和模块
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern {
    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

// 基础外部库
extern crate hex;
use std::time::Instant;

// 引入 Intel SGX 相关的数据类型和功能 库在toml中引入
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;

// 引入结构体，结构体的定义是从 Protocol Buffers 文件自动生成的。
use secure_aggregation::aggregator_server::{Aggregator, AggregatorServer};
use secure_aggregation::{AggregateRequestParameters, AggregateResponseParameters, StartRequestParameters, StartResponseParameters};
// 引入tonic用于构建gRPC服务端和客户端的库
use tonic::{transport::Server, Request, Response, Status};
// 引入自动生成的gRPC服务端和消息格式的模块
pub mod secure_aggregation {
    tonic::include_proto!("secure_aggregation");
}
// 引入tokio异步运行时库
use tokio::runtime;

// 引入安全增强的ECALL和OCALL函数，并将其中的特定函数导入到当前作用域中
mod ecalls;
use ecalls::{
    ecall_client_size_optimized_secure_aggregation, ecall_fl_init, ecall_secure_aggregation,
    ecall_start_round, init_enclave,
};


// 实现了Aggregator trait对应的start和aggregate方法的具体逻辑
#[tonic::async_trait]
impl Aggregator for CentralServer {
    async fn start(
        &self,
        request: Request<StartRequestParameters>,
    ) -> Result<Response<StartResponseParameters>, Status> {
    	// 处理start请求
        println!("[Server] Got a start request ...");
        // 从请求中获取各种参数
        let fl_id = request.get_ref().fl_id as u32;
        let client_ids = &request.get_ref().client_ids;
        let sigma = request.get_ref().sigma as f32;
        let clipping = request.get_ref().clipping as f32;
        let sampling_ratio = request.get_ref().sampling_ratio as f32;
        let aggregation_alg = request.get_ref().aggregation_alg as u32;

	    // 打印聚合设置信息
        if self.verbose { 
            print_fl_settings(
        	get_algorithm_name(aggregation_alg), 
        	sigma, 
        	clipping, 
        	client_ids.len(), 
        	sampling_ratio, 
        	);
        }

        let mut retval = sgx_status_t::SGX_SUCCESS;
        let mut result = unsafe {
            // 调用ecall_fl_init函数进行初始化
            ecall_fl_init(
                self.enclave_id,
                &mut retval,
                fl_id,
                client_ids.as_ptr() as *const u32,
                client_ids.len(),
                sigma,
                clipping,
                sampling_ratio,
                aggregation_alg,
                bool_to_u8(self.verbose),
                bool_to_u8(self.dp),
            )
        };
        // 检查 ecall_fl_init 函数的调用结果
        if result != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
            panic!("Error at ecall_fl_init")
        }

        // 确定采样客户端
        let sample_size = (sampling_ratio * client_ids.len() as f32) as usize;
        let sampled_client_ids: Vec<u32> = vec![0u32; sample_size];
        result = unsafe {
            // 调用ecall_start_round函数启动聚合的第一轮
            ecall_start_round(
                self.enclave_id,
                &mut retval,
                fl_id,
                0,
                sample_size,
                sampled_client_ids.as_ptr() as *mut u32,
            )
        };
        if result != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
            panic!("Error at ecall_start_round")
        }

        let reply = StartResponseParameters {
            fl_id: fl_id,
            round: 0,
            client_ids: sampled_client_ids,
        };

        println!("[Server] complete preparation");
        Ok(Response::new(reply))
    }


    async fn aggregate(
        &self,
        request: Request<AggregateRequestParameters>,
    ) -> Result<Response<AggregateResponseParameters>, Status> {
        println!("[Server] Got a aggregate request ...");

        // 从请求中提取所需的参数
        let fl_id = request.get_ref().fl_id as u32;
        let round = request.get_ref().round as u32;
        let aggregation_alg = request.get_ref().aggregation_alg as u32;
        let encrypted_parameters_data = &request.get_ref().encrypted_parameters;
        let client_ids = &request.get_ref().client_ids;
        let optimal_num_of_clients = request.get_ref().optimal_num_of_clients as usize;
        if optimal_num_of_clients > client_ids.len() {
            panic!("optimal_num_of_clients is more than client size {}", client_ids.len());
        }

        if self.verbose { print_fl_settings_for_each_round(
            fl_id, round, get_algorithm_name(aggregation_alg)) };
        
        // response
        let updated_parametes_data: Vec<f32> = vec![0f32; num_of_parameters];
        let mut execution_time_results: Vec<f32> = vec![0f32; TIME_KIND];

        let mut retval = sgx_status_t::SGX_SUCCESS;
        let mut result = sgx_status_t::SGX_SUCCESS;

        let start = Instant::now();
        if aggregation_alg == 6 {
            result = unsafe {
                ecall_client_size_optimized_secure_aggregation(
                    self.enclave_id,
                    &mut retval,
                    fl_id,
                    round,
                    optimal_num_of_clients,
                    client_ids.as_ptr() as *const u32,
                    client_ids.len(),
                    encrypted_parameters_data.as_ptr() as *const u8,
                    num_of_parameters,
                    num_of_sparse_parameters,
                    aggregation_alg,
                    updated_parametes_data.as_ptr() as *mut f32,
                    execution_time_results.as_ptr() as *mut f32
                )
            };
            if result != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
                panic!("Error at ecall_client_size_optimized_secure_aggregation")
            }
        } else {
            result = unsafe {
                ecall_secure_aggregation(
                    self.enclave_id,
                    &mut retval,
                    fl_id,
                    round,
                    client_ids.as_ptr() as *const u32,
                    client_ids.len(),
                    encrypted_parameters_data.as_ptr() as *const u8,
                    encrypted_parameters_data.len(),
                    num_of_parameters,
                    num_of_sparse_parameters,
                    aggregation_alg,
                    updated_parametes_data.as_ptr() as *mut f32,
                    execution_time_results.as_ptr() as *mut f32,
                )
            };
            if result != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
                panic!("Error at ecall_secure_aggregation")
            }
        }
        let end = start.elapsed();
        execution_time_results.push(end.as_secs_f32());
        if self.verbose { print_total_execution_time(end.as_secs(), end.subsec_nanos() / 1_000); }

        // Assuming that the next round is the same number of participants.
        let sample_size = client_ids.len();
        let sampled_client_ids: Vec<u32> = vec![0u32; sample_size];
        let next_round = round + 1;
        result = unsafe {
            ecall_start_round(
                self.enclave_id,
                &mut retval,
                fl_id,
                next_round,
                sample_size,
                sampled_client_ids.as_ptr() as *mut u32,
            )
        };
        if result != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
            panic!("[Server] Error at ecall_start_round")
        }

        let reply = AggregateResponseParameters {
            updated_parameters: updated_parametes_data,
            execution_time: end.as_secs_f32(),
            client_ids: sampled_client_ids,
            round: next_round
        };

        println!("[Server] complete the round");
        Ok(Response::new(reply))
    }
}

// 主函数
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 定义服务器地址
    let addr = "0.0.0.0:50051".parse().unwrap();
    
    // 初始化 Enclave
    println!("[Server] init_enclave...");
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[Server] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[Server] Init Enclave Failed {}!", x.as_str());
            panic!("")
        }
    };
    
    // 创建中央服务器对象，使用默认配置
    let mut central_server = CentralServer::default();
    // 将 Enclave 的 ID 设置为中央服务器的 enclave_id
    central_server.enclave_id = enclave.geteid();
    central_server.verbose = true;
    central_server.dp = false;

    // 打印 GRPC 服务器绑定的地址信息
    println!("[Server] Now GRPC Server is binded on {:?}", addr);

    // 创建一个多线程的运行时，启用所有功能，并设置线程堆栈大小
    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(1000000000) // 用于 OCALL 的线程堆栈大小
        .build()
        .expect("failed to build runtime");

    // 创建一个服务器 Future
    let server_future = Server::builder()
        .add_service(AggregatorServer::new(central_server)) // 添加 AggregatorServer 的服务
        .serve(addr); // 在给定地址上启动服务器

    // 使用运行时执行服务器 Future，并检查执行结果
    rt.block_on(server_future).expect("failed to successfully run the future on RunTime");

    // 销毁 Enclave
    enclave.destroy();
    Ok(())
}
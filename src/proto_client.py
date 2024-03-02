import grpc

import secure_aggregation_pb2
import secure_aggregation_pb2_grpc


ADDRESS = '127.0.0.1:50051'
COUNTER_LEN = 16


def call_grpc_aggregate(
    fl_id,
    round,
    encrypted_parameters,
    client_ids,
    aggregation_alg,
    optimal_num_of_clients,
):
    print(f"request 'aggregate' to {ADDRESS}")
    with grpc.insecure_channel(ADDRESS) as channel:
        stub = secure_aggregation_pb2_grpc.AggregatorStub(channel)
        response = stub.Aggregate(
            secure_aggregation_pb2.AggregateRequestParameters(
                fl_id=fl_id,
                round=round,
                encrypted_parameters=bytes(encrypted_parameters),
                aggregation_alg=aggregation_alg,
                optimal_num_of_clients=optimal_num_of_clients,
                client_ids=client_ids,
            )
        )
    return response.updated_parameters, float(response.execution_time), response.client_ids, response.round

# 与GRPC服务器进行通信，并发送"start"请求以启动安全聚合过程
def call_grpc_start(
    fl_id: int,
    client_ids: list,
    sigma: float,
    clipping: float,
    sampling_ratio: float,
    aggregation_alg: int,
):
# fl_id：联邦学习ID
# client_ids：参与联邦学习的客户端ID列表
# sigma：噪声的标准差
# clipping：梯度剪裁的阈值
# sampling_ratio：采样比例
# aggregation_alg：聚合算法的代码
    print(f"request 'start' to {ADDRESS}")
    # 创建一个与GRPC服务器建立的不安全通道
    with grpc.insecure_channel(ADDRESS) as channel:
    	# 使用通道创建AggregatorStub的实例，以便与服务器进行通信
        stub = secure_aggregation_pb2_grpc.AggregatorStub(channel)
        # 调用stub.Start方法，向服务器发送"start"请求，并传递参数对象作为请求的内容。
        response = stub.Start(
            # 构造一个StartRequestParameters对象，其中包含了请求的参数
            secure_aggregation_pb2.StartRequestParameters(
                fl_id=fl_id,
                client_ids=client_ids,
                sigma=sigma,
                clipping=clipping,
                sampling_ratio=sampling_ratio,
                aggregation_alg=aggregation_alg,
            )
        )
    return response.fl_id, response.round, response.client_ids

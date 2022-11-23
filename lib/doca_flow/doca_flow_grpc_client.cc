#include "doca_flow_grpc_client.h"

#include "flow_grpc.grpc.pb.h"
#include "flow_grpc.pb.h"

#include "grpc_orchestrator.grpc.pb.h"
#include "grpc_orchestrator.pb.h"

#include <grpcpp/grpcpp.h>
#include <iterator>
#include <regex>
using namespace grpc;
using namespace flow_grpc;
using namespace std;

using orchestaror::Orchestrator;
using orchestaror::CMD;
using orchestaror::RichStatus;
using orchestaror::Uid;

DOCA_LOG_REGISTER(GRPCFLOWCLIENT);

string match_to_str(struct doca_flow_match *match){
    ostringstream os;
    for(int i=0; i<6;i++)
        os<<int(match->out_dst_mac[i])<<" ";
    for(int i=0; i<6;i++)
        os<<int(match->out_src_mac[i])<<" ";
    os<<match->out_dst_ip.ipv4_addr<<" ";
    os<<match->out_src_ip.ipv4_addr<<" ";
    os<<int(match->out_l4_type)<<" ";
    os<<match->out_dst_port<<" ";
    os<<match->out_src_port<<" ";
    return os.str();
}

string action_to_str(struct doca_flow_actions *action){
    ostringstream os;
    for(int i=0; i<6;i++)
        os<<int(action->mod_dst_mac[i])<<" ";
    for(int i=0; i<6;i++)
        os<<int(action->mod_src_mac[i])<<" ";
    os<<action->mod_dst_ip.ipv4_addr<<" ";
    os<<action->mod_src_ip.ipv4_addr<<" ";
    os<<action->mod_dst_port<<" ";
    os<<action->mod_src_port<<" ";
    return os.str();
}

string fwd_to_str(struct doca_flow_grpc_fwd *fwd){
    ostringstream os;
    if(!fwd || !(fwd->fwd)){
        os<<"null";
        return os.str();
    }
    os<<fwd->next_pipe_id;
    os<<" ";
    os<<fwd->fwd->type;
    os<<" ";
    os<<fwd->fwd->port_id;
    return os.str();
}


class OrchestratorClient{
    private:
        unique_ptr<Orchestrator::Stub> stub_;
        string uid;
    public:
        OrchestratorClient(){}
        OrchestratorClient(shared_ptr<Channel> channel):stub_(Orchestrator::NewStub(channel)){}
        void CreateClient(shared_ptr<Channel> channel){
            this->stub_=Orchestrator::NewStub(channel);
        }
        ~OrchestratorClient(){
            //cout<<"destroy orchestrator client"<<endl;
        }
        void Create(){
            CMD cmd;
            RichStatus status;
            ClientContext context;
            
            cmd.set_cmd_str("flow_grpc_server -l 0-3 -n 4 -F");
            Status result=stub_->Create(&context, cmd, &status);
            if(result.ok()){
                uid = status.uid().uid();
                printf("create grpc_flow_server on uid:%s\n", uid.c_str());
            }else{
                printf("create grpc call failed, status [%s], msg: [%s]\n", 
                result.error_message().c_str(),
                status.err_status().error_msg().c_str());
            }
        }
        void Destroy(){
            Uid _uid;
            orchestaror::Status status;
            ClientContext context;

            _uid.set_uid(uid);
            Status result=stub_->Destroy(&context, _uid, &status);
        }
};
OrchestratorClient orche;

class FlowGrpcClient{
    private:
        unique_ptr<FlowGRPC::Stub> stub_;
    public:
        FlowGrpcClient(){}
        FlowGrpcClient(shared_ptr<Channel> channel):stub_(FlowGRPC::NewStub(channel)){}
        void CreateClient(shared_ptr<Channel> channel){
            this->stub_=FlowGRPC::NewStub(channel);
        }
        ~FlowGrpcClient(){
            // cout<<"destroy flow grpc client"<<endl;
        }
        void EnvInit(struct application_dpdk_config *dpdk_config, struct doca_flow_grpc_response *rep){
            DPDKConfig config;
            config.mutable_app_port_config()->set_nb_hairpin_q(dpdk_config->port_config.nb_hairpin_q);
            config.mutable_app_port_config()->set_nb_ports(dpdk_config->port_config.nb_ports);
            config.mutable_app_port_config()->set_nb_queues(dpdk_config->port_config.nb_queues);
            config.set_reserve_main_thread(dpdk_config->reserve_main_thread);

            Response response;
            ClientContext context;
            printf("----\n");
            grpc::Status result=stub_->EnvInitialize(&context, config,&response);
            if(result.ok()){
                rep->success=true;
            }else{
                printf("%s\n", result.error_message().c_str());
                rep->success=false;
                rep->error.message=result.error_message().c_str();
            }
        }

        void GrpcInit(struct doca_flow_cfg *cfg, struct doca_flow_grpc_response *rep){
            GRPCConfig config;

            Response response;
            ClientContext context;

            Status result=stub_->GRPCInitialize(&context, config, &response);
            if(result.ok()){
                rep->success=true;
            }else{
                rep->success=false;
            }
        }

        void StartPort(struct doca_flow_port_cfg *cfg, struct doca_flow_grpc_response *rep){
            FlowPortConfig config;
            config.set_port_id(cfg->port_id);
            Response response;
            ClientContext context;

            Status result=stub_->PortStart(&context, config, &response);
            if(result.ok()){
                rep->success=true;
            }else{
                rep->success=false;
                rep->error.message=result.error_message().c_str();
            }
        }

        void PairPort(int port_1, int port_2, struct doca_flow_grpc_response *rep){
            PortPairRequest pair_config;
            ClientContext context;
            Response response;

            pair_config.set_port_id1(port_1);
            pair_config.set_port_id2(port_2);

            Status result=stub_->PortPair(&context, pair_config, &response);
            if(result.ok()){
                rep->success=true;
            }else{
                rep->success=false;
                rep->error.message=result.error_message().c_str();
            }
        }

        void EnvDestroy(struct doca_flow_grpc_response *rep){
            EnvDestroyRequest req;
            ClientContext context;
            Response reponse;

            Status result=stub_->EnvDestroy(&context, req, &reponse);
            if(result.ok()){
                rep->success=true;
            }else{
                rep->success=false;
                rep->error.message=result.error_message().c_str();
            }
        }

        void CreatePipe(struct doca_flow_grpc_pipe_cfg *cfg,
		struct doca_flow_grpc_fwd *fwd, struct doca_flow_grpc_fwd *fwd_miss, struct doca_flow_grpc_response *rep)
        {
            int i=0;
            CreatePipeRequest cp;

            cp.mutable_pipe_config()->set_name(string(cfg->cfg->attr.name));
            cp.mutable_pipe_config()->set_is_root(cfg->cfg->attr.is_root);
            cp.mutable_pipe_config()->mutable_match()->set_match_rule(match_to_str(cfg->cfg->match));
            cp.mutable_pipe_config()->mutable_action()->set_action_rule(action_to_str(cfg->cfg->actions));
            cp.mutable_fwd()->set_fwd_rule(fwd_to_str(fwd));
            cp.mutable_fwd_miss()->set_fwd_rule(fwd_to_str(fwd_miss));
            // printf("    fwd_str: %s, fwd_miss_str: %s\n", cp.fwd().fwd_rule().c_str(), cp.fwd_miss().fwd_rule().c_str());            
            Response reponse;
            ClientContext context;
            Status result=stub_->CreatePipe(&context, cp, &reponse);
            if(result.ok()){
                rep->success=true;
                rep->pipe_id=reponse.pipe_id();
            }else{
                rep->success=false;
                rep->error.message=result.error_message().c_str();
            }
        }

        void PipeAddEntry(uint64_t pipe_id, struct doca_flow_match *match, 
        struct doca_flow_actions *action, struct doca_flow_grpc_fwd *fwd,
        struct doca_flow_grpc_response *rep){
            AddEntryRequest ae;
            ClientContext context;
            Response response;
            ae.set_pipe_id(pipe_id);
            ae.mutable_match()->set_match_rule(match_to_str(match));
            ae.mutable_action()->set_action_rule(action_to_str(action));
            ae.mutable_fwd()->set_fwd_rule(fwd_to_str(fwd));
            
            //printf("Add Entry: pipe_id-%d\n", pipe_id);
            Status result=stub_->AddEntry(&context, ae, &response);
            if(result.ok()){
                rep->success=true;
            }else{
                // printf("    %s\n", result.error_message().c_str());
                rep->success=false;
                rep->error.message=result.error_message().c_str();
            }
        }
};

FlowGrpcClient flow_grpc_client;

void doca_flow_grpc_client_create(char *grpc_address){
    
    string orchestrator_grpc_address=grpc_address;
    string flow_grpc_address=grpc_address;
    orchestrator_grpc_address+=":50051";
    flow_grpc_address+=":50050";    
    
    //printf("trying to connect orchestrator: %s\n", orchestrator_grpc_address.c_str());
    orche.CreateClient(CreateChannel((orchestrator_grpc_address), InsecureChannelCredentials()));
    orche.Create();
    sleep(3);
    flow_grpc_client.CreateClient(CreateChannel((flow_grpc_address), InsecureChannelCredentials()));
    //printf("create grpc_flow_server on %s\n", flow_grpc_address.c_str());
}

struct doca_flow_grpc_response doca_flow_grpc_env_init(struct application_dpdk_config *dpdk_config){
    struct doca_flow_grpc_response rep;
    flow_grpc_client.EnvInit(dpdk_config, &rep);
    if(rep.success){
        printf("grpc flow server initialize successfully\n");
    }
    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_init(struct doca_flow_cfg *cfg){
    struct doca_flow_grpc_response rep;
    
    flow_grpc_client.GrpcInit(cfg, &rep);

    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_port_start(struct doca_flow_port_cfg *cfg){
    struct doca_flow_grpc_response rep;
    flow_grpc_client.StartPort(cfg, &rep);
    if(rep.success){
        printf("port %d start successfully\n", cfg->port_id);
    }
    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_port_pair(uint16_t port_id, uint16_t pair_port_id){
    struct doca_flow_grpc_response rep;
    
    // flow_grpc_client.PairPort(port_id, pair_port_id, &rep);
    rep.success=true;
    return rep;
}




struct doca_flow_grpc_response doca_flow_grpc_pipe_create(struct doca_flow_grpc_pipe_cfg *cfg,
		struct doca_flow_grpc_fwd *fwd, struct doca_flow_grpc_fwd *fwd_miss){
    
    struct doca_flow_grpc_response rep;
    // printf("try to create pipe: %s\n", cfg->cfg->name);
    flow_grpc_client.CreatePipe(cfg, fwd, fwd_miss, &rep);
    if(rep.success){
        DOCA_LOG_INFO("create pipe successfully, with pipe_id: %d", rep.pipe_id);
    }
    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_pipe_add_entry(uint16_t pipe_queue,
		uint64_t pipe_id, struct doca_flow_match *match, struct doca_flow_actions *actions,
		struct doca_flow_monitor *monitor, struct doca_flow_grpc_fwd *client_fwd, uint32_t flags){
    struct doca_flow_grpc_response rep;
    
    flow_grpc_client.PipeAddEntry(pipe_id, match, actions, client_fwd, &rep);
    if(rep.success){
        DOCA_LOG_INFO("added entry to pipe-%d", pipe_id);
    }
    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_port_pipes_dump(uint16_t port_id, FILE *f){
    struct doca_flow_grpc_response rep;
    
    //...
    rep.success=true;
    //...

    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_query(uint64_t entry_id, struct doca_flow_query *query_stats){
    struct doca_flow_grpc_response rep;
    
    //...
    rep.success=true;
    //...

    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_port_pipes_flush(uint16_t port_id){
    struct doca_flow_grpc_response rep;
    
    //...
    rep.success=true;
    //...

    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_pipe_rm_entry(uint16_t pipe_queue, uint64_t entry_id){
    struct doca_flow_grpc_response rep;
    
    //...
    rep.success=true;
    //...

    return rep;
}



struct doca_flow_grpc_response doca_flow_grpc_pipe_destroy(uint64_t pipe_id){
    struct doca_flow_grpc_response rep;
    
    //...
    rep.success=true;
    //...

    return rep;
}

struct doca_flow_grpc_response doca_flow_grpc_control_pipe_add_entry(uint16_t pipe_queue, uint8_t priority,
		uint64_t pipe_id, struct doca_flow_match *match,
		struct doca_flow_match *match_mask, struct doca_flow_grpc_fwd *client_fwd){
    struct doca_flow_grpc_response rep;
    
    //...
    rep.success=true;
    //...

    return rep;
}

void doca_flow_grpc_destroy(void){
    struct doca_flow_grpc_response rep;
    
    flow_grpc_client.EnvDestroy(&rep);

}

struct doca_flow_grpc_response doca_flow_grpc_env_destroy(void){
    
    orche.Destroy();

    flow_grpc_client.~FlowGrpcClient();
    orche.~OrchestratorClient();
}


/*
void print_match(struct doca_flow_match *match){
    printf("    out-dst-mac:%2x %2x %2x %2x% 2x %2x\n", 
    match->out_dst_mac[0],match->out_dst_mac[1], 
    match->out_dst_mac[2],match->out_dst_mac[3],
    match->out_dst_mac[4],match->out_dst_mac[5]);

    printf("    out-src-mac:%2x %2x %2x %2x% 2x %2x\n", 
    match->out_src_mac[0],match->out_src_mac[1], 
    match->out_src_mac[2],match->out_src_mac[3],
    match->out_src_mac[4],match->out_src_mac[5]);

    printf("    out-dst-ip: %d\n", match->out_dst_ip.ipv4_addr);
    printf("    out-src-ip: %d\n", match->out_src_ip.ipv4_addr);
    
    printf("    out-l4-type:%d\n", match->out_l4_type);

    printf("    out-dst-port:%d\n", match->out_dst_port);
    printf("    out-src-port:%d\n", match->out_src_port);
}*/
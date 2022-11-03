#include "SimpleFlow.grpc.pb.h"
#include "SimpleFlow.pb.h"

#include <grpcpp/grpcpp.h>

#include <iterator>
#include <regex>

using namespace grpc;
using namespace simple_flow_offload;
using namespace std;

template< typename... Args >
std::string string_format(const char* format, Args... args)
{
    size_t length = std::snprintf(nullptr, 0, format, args...);
    if (length <= 0)
    {
        return "";
    }

    char* buf = new char[length + 1];
    std::snprintf(buf, length + 1, format, args...);

    std::string str(buf);
    delete[] buf;
    return std::move(str);
}

class FlowCreator{
    private:
        unique_ptr<SimpleFlowOffload::Stub> stub_;
    public:
        FlowCreator(shared_ptr<Channel> channel):stub_(SimpleFlowOffload::NewStub(channel)) {}

        string CreateFlow(string match, string action, string fwd){
            FlowRule rule;
            rule.set_match(match);
            rule.set_action(action);
            rule.set_fwd(fwd);
            
            Reply rep;
            ClientContext context;

            Status status=stub_->CreateFlow(&context, rule, &rep);

            if(!status.ok()){
                return "Error: "+status.error_message();
            }else{
                return "Flow create successfully";
            }
        }
};
std::vector<std::string> s_split(const std::string& in, const std::string& delim) {
    std::regex re{ delim };
    // 调用 std::vector::vector (InputIterator first, InputIterator last,const allocator_type& alloc = allocator_type())
    // 构造函数,完成字符串分割
    return std::vector<std::string> {
        std::sregex_token_iterator(in.begin(), in.end(), re, -1),
            std::sregex_token_iterator()
    };
}

int main(){
    string address;
    string cmd;
        
    cout<<"Remote Flow Creator"<<endl;
    cout<<">> Connect remote service: ";
    getline(cin,address);
    FlowCreator sfo(CreateChannel(address, InsecureChannelCredentials()));
    cout<<">> Created to "<<address<<endl;
    
    while(true){
        cout<<">> ";
        getline(cin, cmd);
        /*
create_flow dst_mac=b0:7b:25:25:ee:d8,src_mac=b0:7b:25:25:ee:d9,dst_ip=192.168.1.114,src_ip=192.168.1.112,l4_type=tcp,dst_port=10000,src_port=10001 mod_dst_mac=b0:7b:25:25:ee:da fwd_port=1
        */
        vector<string> c = s_split(cmd, " ");
        if(c[0]=="create_flow"){
            cout<<"Try to create flow: "<<endl;
            cout<<"     match: "<<c[1]<<endl;
            cout<<"    action: "<<c[2]<<endl;
            cout<<"       fwd: "<<c[3]<<endl;
            cout<< sfo.CreateFlow(c[1],c[2],c[3])<<endl;
        }
    }
    return 0;
}
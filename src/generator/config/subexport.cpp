#include <algorithm>
#include <iostream>
#include <numeric>
#include <cmath>
#include <climits>

#include "config/regmatch.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "handler/settings.h"
#include "parser/config/proxy.h"
#include "script/script_quickjs.h"
#include "utils/bitwise.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/stl_extra.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "nodemanip.h"
#include "ruleconvert.h"

extern string_array ss_ciphers, ssr_ciphers;

const string_array clashr_protocols = {"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"};
const string_array clashr_obfs = {"plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"};
const string_array clash_ssr_ciphers = {"rc4-md5", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "chacha20-ietf", "xchacha20", "none"};

std::string vmessLinkConstruct(const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &path, const std::string &host, const std::string &tls)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.Key("v");
    writer.String("2");
    writer.Key("ps");
    writer.String(remarks.data());
    writer.Key("add");
    writer.String(add.data());
    writer.Key("port");
    writer.String(port.data());
    writer.Key("type");
    writer.String(type.empty() ? "none" : type.data());
    writer.Key("id");
    writer.String(id.data());
    writer.Key("aid");
    writer.String(aid.data());
    writer.Key("net");
    writer.String(net.empty() ? "tcp" : net.data());
    writer.Key("path");
    writer.String(path.data());
    writer.Key("host");
    writer.String(host.data());
    writer.Key("tls");
    writer.String(tls.data());
    writer.EndObject();
    return sb.GetString();
}

bool matchRange(const std::string &range, int target)
{
    string_array vArray = split(range, ",");
    bool match = false;
    std::string range_begin_str, range_end_str;
    int range_begin, range_end;
    static const std::string reg_num = "-?\\d+", reg_range = "(\\d+)-(\\d+)", reg_not = "\\!-?(\\d+)", reg_not_range = "\\!(\\d+)-(\\d+)", reg_less = "(\\d+)-", reg_more = "(\\d+)\\+";
    for(std::string &x : vArray)
    {
        if(regMatch(x, reg_num))
        {
            if(to_int(x, INT_MAX) == target)
                match = true;
        }
        else if(regMatch(x, reg_range))
        {
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if(target >= range_begin && target <= range_end)
                match = true;
        }
        else if(regMatch(x, reg_not))
        {
            match = true;
            if(to_int(regReplace(x, reg_not, "$1"), INT_MAX) == target)
                match = false;
        }
        else if(regMatch(x, reg_not_range))
        {
            match = true;
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if(target >= range_begin && target <= range_end)
                match = false;
        }
        else if(regMatch(x, reg_less))
        {
            if(to_int(regReplace(x, reg_less, "$1"), INT_MAX) >= target)
                match = true;
        }
        else if(regMatch(x, reg_more))
        {
            if(to_int(regReplace(x, reg_more, "$1"), INT_MIN) <= target)
                match = true;
        }
    }
    return match;
}

bool applyMatcher(const std::string &rule, std::string &real_rule, const Proxy &node)
{
    std::string target, ret_real_rule;
    static const std::string groupid_regex = R"(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)", group_regex = R"(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)";
    static const std::string type_regex = R"(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)", port_regex = R"(^!!(?:PORT)=(.+?)(?:!!(.*))?$)", server_regex = R"(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)";
    static const std::map<ProxyType, const char *> types = {
        {ProxyType::Shadowsocks,  "SS"},
        {ProxyType::ShadowsocksR, "SSR"},
        {ProxyType::VMess,        "VMESS"},
        {ProxyType::VLESS,        "VLESS"},
        {ProxyType::Trojan,       "TROJAN"},
        {ProxyType::Snell,        "SNELL"},
        {ProxyType::HTTP,         "HTTP"},
        {ProxyType::HTTPS,        "HTTPS"},
        {ProxyType::SOCKS5,       "SOCKS5"},
        {ProxyType::WireGuard,    "WIREGUARD"},
        {ProxyType::Hysteria,     "HYSTERIA"},
        {ProxyType::Hysteria2,    "HYSTERIA2"},
        {ProxyType::TUIC,         "TUIC"},
        {ProxyType::AnyTLS,       "ANYTLS"}
    };
    if(startsWith(rule, "!!GROUP="))
    {
        regGetMatch(rule, group_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Group, target);
    }
    else if(startsWith(rule, "!!GROUPID=") || startsWith(rule, "!!INSERT="))
    {
        int dir = startsWith(rule, "!!INSERT=") ? -1 : 1;
        regGetMatch(rule, groupid_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, dir * node.GroupId);
    }
    else if(startsWith(rule, "!!TYPE="))
    {
        regGetMatch(rule, type_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        if(node.Type == ProxyType::Unknown || types.find(node.Type) == types.end())
            return false;
        return regMatch(types.at(node.Type), target);
    }
    else if(startsWith(rule, "!!PORT="))
    {
        regGetMatch(rule, port_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, node.Port);
    }
    else if(startsWith(rule, "!!SERVER="))
    {
        regGetMatch(rule, server_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Hostname, target);
    }
    else
        real_rule = rule;
    return true;
}

void processRemark(std::string &remark, const string_array &remarks_list, bool proc_comma = true)
{
    // Replace every '=' with '-' in the remark string to avoid parse errors from the clients.
    //     Surge is tested to yield an error when handling '=' in the remark string,
    //     not sure if other clients have the same problem.
    std::replace(remark.begin(), remark.end(), '=', '-');

    if(proc_comma)
    {
        if(remark.find(',') != std::string::npos)
        {
            remark.insert(0, "\"");
            remark.append("\"");
        }
    }
    std::string tempRemark = remark;
    int cnt = 2;
    while(std::find(remarks_list.cbegin(), remarks_list.cend(), tempRemark) != remarks_list.cend())
    {
        tempRemark = remark + " " + std::to_string(cnt);
        cnt++;
    }
    remark = tempRemark;
}

void groupGenerate(const std::string &rule, std::vector<Proxy> &nodelist, string_array &filtered_nodelist, bool add_direct, extra_settings &ext)
{
    std::string real_rule;
    if(startsWith(rule, "[]") && add_direct)
    {
        filtered_nodelist.emplace_back(rule.substr(2));
    }
#ifndef NO_JS_RUNTIME
    else if(startsWith(rule, "script:") && ext.authorized)
    {
        script_safe_runner(ext.js_runtime, ext.js_context, [&](qjs::Context &ctx){
            std::string script = fileGet(rule.substr(7), true);
            try
            {
                ctx.eval(script);
                auto filter = (std::function<std::string(const std::vector<Proxy>&)>) ctx.eval("filter");
                std::string result_list = filter(nodelist);
                filtered_nodelist = split(regTrim(result_list), "\n");
            }
            catch (qjs::exception)
            {
                script_print_stack(ctx);
            }
        }, global.scriptCleanContext);
    }
#endif // NO_JS_RUNTIME
    else
    {
        for(Proxy &x : nodelist)
        {
            if(applyMatcher(rule, real_rule, x) && (real_rule.empty() || regFind(x.Remark, real_rule)) && std::find(filtered_nodelist.begin(), filtered_nodelist.end(), x.Remark) == filtered_nodelist.end())
                filtered_nodelist.emplace_back(x.Remark);
        }
    }
}

void proxyToClash(std::vector<Proxy> &nodes, YAML::Node &yamlnode, const ProxyGroupConfigs &extra_proxy_group, bool clashR, extra_settings &ext)
{
    YAML::Node proxies, original_groups;
    std::vector<Proxy> nodelist;
    string_array remarks_list;
    /// proxies style
    bool proxy_block = false, proxy_compact = false, group_block = false, group_compact = false;
    switch(hash_(ext.clash_proxies_style))
    {
    case "block"_hash:
        proxy_block = true;
        break;
    default:
    case "flow"_hash:
        break;
    case "compact"_hash:
        proxy_compact = true;
        break;
    }
    switch(hash_(ext.clash_proxy_groups_style))
    {
        case "block"_hash:
            group_block = true;
            break;
        default:
        case "flow"_hash:
            break;
        case "compact"_hash:
            group_compact = true;
            break;
    }

    for(Proxy &x : nodes)
    {
        YAML::Node singleproxy;

        std::string type = getProxyTypeName(x.Type);
        std::string pluginopts = replaceAllDistinct(x.PluginOption, ";", "&");
        if(ext.append_proxy_type)
            x.Remark = "[" + type + "] " + x.Remark;

        processRemark(x.Remark, remarks_list, false);

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);

        singleproxy["name"] = x.Remark;
        singleproxy["server"] = x.Hostname;
        singleproxy["port"] = x.Port;

        if (!x.UnderlyingProxy.empty())
            singleproxy["dialer-proxy"] = x.UnderlyingProxy;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            //latest clash core removed support for chacha20 encryption
            if(ext.filter_deprecated && x.EncryptMethod == "chacha20")
                continue;
            singleproxy["type"] = "ss";
            singleproxy["cipher"] = x.EncryptMethod;
            singleproxy["password"] = x.Password;
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["password"].SetTag("str");
            switch(hash_(x.Plugin))
            {
            case "simple-obfs"_hash:
            case "obfs-local"_hash:
                singleproxy["plugin"] = "obfs";
                singleproxy["plugin-opts"]["mode"] = urlDecode(getUrlArg(pluginopts, "obfs"));
                singleproxy["plugin-opts"]["host"] = urlDecode(getUrlArg(pluginopts, "obfs-host"));
                break;
            case "v2ray-plugin"_hash:
                singleproxy["plugin"] = "v2ray-plugin";
                singleproxy["plugin-opts"]["mode"] = getUrlArg(pluginopts, "mode");
                singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
                singleproxy["plugin-opts"]["path"] = getUrlArg(pluginopts, "path");
                singleproxy["plugin-opts"]["tls"] = pluginopts.find("tls") != std::string::npos;
                singleproxy["plugin-opts"]["mux"] = pluginopts.find("mux") != std::string::npos;
                if(!scv.is_undef())
                    singleproxy["plugin-opts"]["skip-cert-verify"] = scv.get();
                break;
            }
            break;
        case ProxyType::VMess:
            singleproxy["type"] = "vmess";
            singleproxy["uuid"] = x.UserId;
            singleproxy["alterId"] = x.AlterId;
            singleproxy["cipher"] = x.EncryptMethod;
            singleproxy["tls"] = x.TLSSecure;
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.ServerName.empty())
                singleproxy["servername"] = x.ServerName;
            else if(!x.SNI.empty())
                singleproxy["servername"] = x.SNI;
            switch(hash_(x.TransferProtocol))
            {
            case "tcp"_hash:
                break;
            case "ws"_hash:
                singleproxy["network"] = x.TransferProtocol;
                if(ext.clash_new_field_name)
                {
                    singleproxy["ws-opts"]["path"] = x.Path;
                    if(!x.Host.empty())
                        singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                    if(!x.Edge.empty())
                        singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                }
                else
                {
                    singleproxy["ws-path"] = x.Path;
                    if(!x.Host.empty())
                        singleproxy["ws-headers"]["Host"] = x.Host;
                    if(!x.Edge.empty())
                        singleproxy["ws-headers"]["Edge"] = x.Edge;
                }
                break;
            case "http"_hash:
                singleproxy["network"] = x.TransferProtocol;
                singleproxy["http-opts"]["method"] = "GET";
                singleproxy["http-opts"]["path"].push_back(x.Path);
                if(!x.Host.empty())
                    singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                if(!x.Edge.empty())
                    singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                break;
            case "h2"_hash:
                singleproxy["network"] = x.TransferProtocol;
                singleproxy["h2-opts"]["path"] = x.Path;
                if(!x.Host.empty())
                    singleproxy["h2-opts"]["host"].push_back(x.Host);
                break;
            case "grpc"_hash:
            {
                singleproxy["network"] = x.TransferProtocol;
                if(!x.Host.empty())
                    singleproxy["servername"] = x.Host;
                std::string grpc_srv = !x.GRPCServiceName.empty() ? urlDecode(x.GRPCServiceName) : x.Path;
                if(!grpc_srv.empty())
                    singleproxy["grpc-opts"]["grpc-service-name"] = grpc_srv;
                break;
            }
            default:
                continue;
            }
            if(!x.Alpn.empty())
                singleproxy["alpn"] = x.Alpn;
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            break;
        case ProxyType::ShadowsocksR:
            //ignoring all nodes with unsupported obfs, protocols and encryption
            if(ext.filter_deprecated)
            {
                if(!clashR && std::find(clash_ssr_ciphers.cbegin(), clash_ssr_ciphers.cend(), x.EncryptMethod) == clash_ssr_ciphers.cend())
                    continue;
                if(std::find(clashr_protocols.cbegin(), clashr_protocols.cend(), x.Protocol) == clashr_protocols.cend())
                    continue;
                if(std::find(clashr_obfs.cbegin(), clashr_obfs.cend(), x.OBFS) == clashr_obfs.cend())
                    continue;
            }

            singleproxy["type"] = "ssr";
            singleproxy["cipher"] = x.EncryptMethod == "none" ? "dummy" : x.EncryptMethod;
            singleproxy["password"] = x.Password;
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["password"].SetTag("str");
            singleproxy["protocol"] = x.Protocol;
            singleproxy["obfs"] = x.OBFS;
            if(clashR)
            {
                singleproxy["protocolparam"] = x.ProtocolParam;
                singleproxy["obfsparam"] = x.OBFSParam;
            }
            else
            {
                singleproxy["protocol-param"] = x.ProtocolParam;
                singleproxy["obfs-param"] = x.OBFSParam;
            }
            break;
        case ProxyType::SOCKS5:
            singleproxy["type"] = "socks5";
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Password.empty())
            {
                singleproxy["password"] = x.Password;
                if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
                    singleproxy["password"].SetTag("str");
            }
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            break;
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            singleproxy["type"] = "http";
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Password.empty())
            {
                singleproxy["password"] = x.Password;
                if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
                    singleproxy["password"].SetTag("str");
            }
            singleproxy["tls"] = x.TLSSecure;
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            break;
        case ProxyType::Trojan:
            singleproxy["type"] = "trojan";
            singleproxy["password"] = x.Password;
            if(!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            else if(!x.Host.empty())
                singleproxy["sni"] = x.Host;
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["password"].SetTag("str");
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.Alpn.empty())
                singleproxy["alpn"] = x.Alpn;
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            switch(hash_(x.TransferProtocol))
            {
            case "tcp"_hash:
                break;
            case "grpc"_hash:
            {
                singleproxy["network"] = x.TransferProtocol;
                std::string grpc_srv = !x.GRPCServiceName.empty() ? urlDecode(x.GRPCServiceName) : x.Path;
                if(!grpc_srv.empty())
                    singleproxy["grpc-opts"]["grpc-service-name"] = grpc_srv;
                break;
            }
            case "ws"_hash:
                singleproxy["network"] = x.TransferProtocol;
                singleproxy["ws-opts"]["path"] = x.Path;
                if(!x.Host.empty())
                    singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                if(!x.Edge.empty())
                    singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                break;
            }
            break;
        case ProxyType::Snell:
            singleproxy["type"] = "snell";
            singleproxy["psk"] = x.Password;
            if(x.SnellVersion != 0)
                singleproxy["version"] = x.SnellVersion;
            if(!x.OBFS.empty())
            {
                singleproxy["obfs-opts"]["mode"] = x.OBFS;
                if(!x.Host.empty())
                    singleproxy["obfs-opts"]["host"] = x.Host;
            }
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["password"].SetTag("str");
            break;
        case ProxyType::WireGuard:
            singleproxy["type"] = "wireguard";
            singleproxy["public-key"] = x.PublicKey;
            singleproxy["private-key"] = x.PrivateKey;
            singleproxy["ip"] = x.SelfIP;
            if(!x.SelfIPv6.empty())
                singleproxy["ipv6"] = x.SelfIPv6;
            if(!x.PreSharedKey.empty())
                singleproxy["preshared-key"] = x.PreSharedKey;
            if(!x.DnsServers.empty())
                singleproxy["dns"] = x.DnsServers;
            if(x.Mtu > 0)
                singleproxy["mtu"] = x.Mtu;
            break;
        case ProxyType::Hysteria:
            singleproxy["type"] = "hysteria";
            if (!x.Ports.empty())
                singleproxy["ports"] = x.Ports;
            if (!x.Protocol.empty())
                singleproxy["protocol"] = x.Protocol;
            if (!x.OBFSParam.empty())
                singleproxy["obfs-protocol"] = x.OBFSParam;
            if (!x.Up.empty())
                singleproxy["up"] = x.Up;
            if (x.UpSpeed)
                singleproxy["up-speed"] = x.UpSpeed;
            if (!x.Down.empty())
                singleproxy["down"] = x.Down;
            if (x.DownSpeed)
                singleproxy["down-speed"] = x.DownSpeed;
            if (!x.AuthStr.empty())
            {
                singleproxy["auth-str"] = x.AuthStr;
                singleproxy["auth"] = base64Encode(x.AuthStr);
            }
            if (!x.OBFS.empty())
                singleproxy["obfs"] = x.OBFS;
            if (!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if (!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if (!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if (!x.Alpn.empty())
                singleproxy["alpn"] = x.Alpn;
            if (!x.Ca.empty())
                singleproxy["ca"] = x.Ca;
            if (!x.CaStr.empty())
                singleproxy["ca-str"] = x.CaStr;
            if (x.RecvWindowConn)
                singleproxy["recv-window-conn"] = x.RecvWindowConn;
            if (x.RecvWindow)
                singleproxy["recv-window"] = x.RecvWindow;
            if (!x.DisableMtuDiscovery.is_undef())
                singleproxy["disable-mtu-discovery"] = x.DisableMtuDiscovery.get();
            if (!x.TCPFastOpen.is_undef())
                singleproxy["fast-open"] = x.TCPFastOpen.get();
            if (x.HopInterval)
                singleproxy["hop-interval"] = x.HopInterval;
            break;
        case ProxyType::Hysteria2:
            singleproxy["type"] = "hysteria2";
            if (!x.Ports.empty())
                singleproxy["ports"] = x.Ports;
            if (!x.Mport.empty())
                singleproxy["mport"] = x.Mport;
            if (x.UpSpeed)
                singleproxy["up"] = x.UpSpeed;
            else if (!x.Up.empty())
                singleproxy["up"] = x.Up;
            if (x.DownSpeed)
                singleproxy["down"] = x.DownSpeed;
            else if (!x.Down.empty())
                singleproxy["down"] = x.Down;
            if (!x.Password.empty())
                singleproxy["password"] = x.Password;
            if (!x.OBFS.empty())
                singleproxy["obfs"] = x.OBFS;
            if (!x.OBFSParam.empty())
                singleproxy["obfs-password"] = x.OBFSParam;
            if (!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if (!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if (!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if (!x.Alpn.empty())
                singleproxy["alpn"] = x.Alpn;
            if (!x.Ca.empty())
                singleproxy["ca"] = x.Ca;
            if (!x.CaStr.empty())
                singleproxy["ca-str"] = x.CaStr;
            if (x.CWND)
                singleproxy["cwnd"] = x.CWND;
            if (x.HopInterval)
                singleproxy["hop-interval"] = x.HopInterval;
            break;
        case ProxyType::TUIC:
            singleproxy["type"] = "tuic";
            if (!x.UUID.empty())
                singleproxy["uuid"] = x.UUID;
            if (!x.Password.empty())
                singleproxy["password"] = x.Password;
            if (!x.HeartbeatInterval.empty())
                singleproxy["heartbeat-interval"] = x.HeartbeatInterval;
            if (!x.Alpn.empty())
                singleproxy["alpn"] = x.Alpn;
            if (!x.FastOpen.is_undef())
                singleproxy["fast-open"] = x.FastOpen.get();
            if (!x.UdpRelayMode.empty())
                singleproxy["udp-relay-mode"] = x.UdpRelayMode;
            if (!x.CongestionController.empty())
                singleproxy["congestion-controller"] = x.CongestionController;
            if (!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if (!x.DisableSNI.is_undef())
                singleproxy["disable-sni"] = x.DisableSNI.get();
            if (!x.ReduceRTT.is_undef())
                singleproxy["reduce-rtt"] = x.ReduceRTT.get();
            if (x.RequestTimeout != 0)
                singleproxy["request-timeout"] = x.RequestTimeout;
            if (x.MaxUdpRelayPacketSize != 0)
                singleproxy["max-udp-relay-packet-size"] = x.MaxUdpRelayPacketSize;
            if (x.MaxOpenStreams != 0)
                singleproxy["max-open-streams"] = x.MaxOpenStreams;
            if (!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            break;
        case ProxyType::AnyTLS:
            singleproxy["type"] = "anytls";
            if (!x.Password.empty())
                singleproxy["password"] = x.Password;
            if (!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if (!x.Alpn.empty())
                singleproxy["alpn"] = x.Alpn;
            if (!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if (x.IdleSessionCheckInterval != 0)
                singleproxy["idle-session-check-interval"] = x.IdleSessionCheckInterval;
            if (x.IdleSessionTimeout != 0)
                singleproxy["idle-session-timeout"] = x.IdleSessionTimeout;
            if (x.MinIdleSession != 0)
                singleproxy["min-idle-session"] = x.MinIdleSession;
            if (!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            break;
        case ProxyType::VLESS:
            singleproxy["type"] = "vless";
            singleproxy["tls"] = x.TLSSecure || !x.PublicKey.empty();
            // Output packet-encoding, xudp, packet-addr only if explicitly set
            if (!x.PacketEncoding.empty())
                singleproxy["packet-encoding"] = x.PacketEncoding;
            if (!x.XUDP.is_undef())
                singleproxy["xudp"] = x.XUDP.get();
            if (!x.PacketAddr.is_undef())
                singleproxy["packet-addr"] = x.PacketAddr.get();
            if (!x.UUID.empty())
                singleproxy["uuid"] = x.UUID;
            if (!x.SNI.empty())
                singleproxy["servername"] = x.SNI;
            if (!x.Alpn.empty())
                singleproxy["alpn"] = x.Alpn;
            if (!x.VlessEncryption.empty())
                singleproxy["encryption"] = x.VlessEncryption;

            switch(hash_(x.TransferProtocol))
            {
                case "tcp"_hash:
                    if(!x.Host.empty())
                        singleproxy["host"] = x.Host;
                    if(!x.Path.empty())
                        singleproxy["path"] = x.Path;
                    break;
                case "ws"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    if(ext.clash_new_field_name)
                    {
                        if(!x.Path.empty())
                            singleproxy["ws-opts"]["path"] = x.Path;
                        if(!x.Host.empty())
                            singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                        if(!x.Edge.empty())
                            singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                        if(!x.V2rayHttpUpgrade.is_undef())
                            singleproxy["ws-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                    }
                    else
                    {
                        if(!x.Path.empty())
                            singleproxy["ws-path"] = x.Path;
                        if(!x.Host.empty())
                            singleproxy["ws-headers"]["Host"] = x.Host;
                        if(!x.Edge.empty())
                            singleproxy["ws-headers"]["Edge"] = x.Edge;
                    }
                    break;
                case "http"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    singleproxy["http-opts"]["method"] = "GET";
                    if(!x.Path.empty())
                        singleproxy["http-opts"]["path"].push_back(x.Path);
                    if(!x.Host.empty())
                        singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                    if(!x.Edge.empty())
                        singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                    break;
                case "h2"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    if(!x.Path.empty())
                        singleproxy["h2-opts"]["path"] = x.Path;
                    if(!x.Host.empty())
                        singleproxy["h2-opts"]["host"].push_back(x.Host);
                    break;
                case "grpc"_hash:
                {
                    singleproxy["network"] = x.TransferProtocol;
                    if(!x.GRPCMode.empty())
                        singleproxy["grpc-opts"]["grpc-mode"] = x.GRPCMode;
                    std::string grpc_srv = !x.GRPCServiceName.empty() ? urlDecode(x.GRPCServiceName) : x.Path;
                    if(!grpc_srv.empty())
                        singleproxy["grpc-opts"]["grpc-service-name"] = grpc_srv;
                    break;
                }
                default:
                    break;
            }

            if (!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if (x.XTLS == 2) {
                singleproxy["flow"] = "xtls-rprx-vision";
            } else if (!x.FlowSet.is_undef() && x.FlowSet.get()) {
                // Output flow field if it was explicitly set (even if empty)
                singleproxy["flow"] = x.Flow;
            } else if (!x.Flow.empty()) {
                // Fallback for backward compatibility
                singleproxy["flow"] = x.Flow;
            }
            if (!x.PublicKey.empty()) {
                singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                singleproxy["reality-opts"]["short-id"] = x.ShortID;
                if (!x.ClientFingerprint.empty()) {
                    singleproxy["client-fingerprint"] = x.ClientFingerprint;
                } else if (!x.Fingerprint.empty()) {
                    singleproxy["client-fingerprint"] = x.Fingerprint;
                } else {
                    singleproxy["client-fingerprint"] = "chrome";
                }
            } else if (!x.ClientFingerprint.empty()) {
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            }
            if (!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            break;
        default:
            continue;
        }

        // UDP is not supported yet in clash using snell
        // sees in https://dreamacro.github.io/clash/configuration/outbound.html#snell
        // Output UDP field when explicitly provided (true or false)
        if(!udp.is_undef() && x.Type != ProxyType::Snell)
            singleproxy["udp"] = udp.get();
        if(!tfo.is_undef())
            singleproxy["tfo"] = tfo.get();
        if(proxy_block)
            singleproxy.SetStyle(YAML::EmitterStyle::Block);
        else
            singleproxy.SetStyle(YAML::EmitterStyle::Flow);
        proxies.push_back(singleproxy);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if(proxy_compact)
        proxies.SetStyle(YAML::EmitterStyle::Flow);

    if(ext.nodelist)
    {
        YAML::Node provider;
        provider["proxies"] = proxies;
        yamlnode.reset(provider);
        return;
    }

    if(ext.clash_new_field_name)
        yamlnode["proxies"] = proxies;
    else
        yamlnode["Proxy"] = proxies;


    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        YAML::Node singlegroup;
        string_array filtered_nodelist;

        singlegroup["name"] = x.Name;
        if (x.Type == ProxyGroupType::Smart)
            singlegroup["type"] = "url-test";
        else
            singlegroup["type"] = x.TypeStr();

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::Relay:
            break;
        case ProxyGroupType::LoadBalance:
            singlegroup["strategy"] = x.StrategyStr();
            [[fallthrough]];
        case ProxyGroupType::Smart:
            [[fallthrough]];
        case ProxyGroupType::URLTest:
            if(!x.Lazy.is_undef())
                singlegroup["lazy"] = x.Lazy.get();
            [[fallthrough]];
        case ProxyGroupType::Fallback:
            singlegroup["url"] = x.Url;
            if(x.Interval > 0)
                singlegroup["interval"] = x.Interval;
            if(x.Tolerance > 0)
                singlegroup["tolerance"] = x.Tolerance;
            break;
        default:
            continue;
        }
        if(!x.DisableUdp.is_undef())
            singlegroup["disable-udp"] = x.DisableUdp.get();

        for(const auto& y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(!x.UsingProvider.empty())
            singlegroup["use"] = x.UsingProvider;
        else
        {
            if(filtered_nodelist.empty())
                filtered_nodelist.emplace_back("DIRECT");
        }
        if(!filtered_nodelist.empty())
            singlegroup["proxies"] = filtered_nodelist;
        if(group_block)
            singlegroup.SetStyle(YAML::EmitterStyle::Block);
        else
            singlegroup.SetStyle(YAML::EmitterStyle::Flow);

        bool replace_flag = false;
        for(auto && original_group : original_groups)
        {
            if(original_group["name"].as<std::string>() == x.Name)
            {
                original_group.reset(singlegroup);
                replace_flag = true;
                break;
            }
        }
        if(!replace_flag)
            original_groups.push_back(singlegroup);
    }

    if(group_compact)
        original_groups.SetStyle(YAML::EmitterStyle::Flow);

    if(ext.clash_new_field_name)
        yamlnode["proxy-groups"] = original_groups;
    else
        yamlnode["Proxy Group"] = original_groups;
}

std::string proxyToClash(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, bool clashR, extra_settings &ext)
{
    YAML::Node yamlnode;

    try
    {
        yamlnode = YAML::Load(base_conf);
    }
    catch (std::exception &e)
    {
        writeLog(0, std::string("Clash base loader failed with error: ") + e.what(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToClash(nodes, yamlnode, extra_proxy_group, clashR, ext);

    if(ext.nodelist)
        return YAML::Dump(yamlnode);

    if(!ext.enable_rule_generator)
        return YAML::Dump(yamlnode);

    if(!ext.managed_config_prefix.empty() || ext.clash_script)
    {
        if(yamlnode["mode"].IsDefined())
        {
            if(ext.clash_new_field_name)
                yamlnode["mode"] = ext.clash_script ? "script" : "rule";
            else
                yamlnode["mode"] = ext.clash_script ? "Script" : "Rule";
        }

        renderClashScript(yamlnode, ruleset_content_array, ext.managed_config_prefix, ext.clash_script, ext.overwrite_original_rules, ext.clash_classical_ruleset);
        return YAML::Dump(yamlnode);
    }

    std::string output_content = rulesetToClashStr(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);
    output_content.insert(0, YAML::Dump(yamlnode));

    return output_content;
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
std::string generatePeer(Proxy &node, bool client_id_as_reserved = false)
{
    std::string result;
    result += "public-key = " + node.PublicKey;
    result += ", endpoint = " + node.Hostname + ":" + std::to_string(node.Port);
    if(!node.PreSharedKey.empty())
        result += ", preshared-key = " + node.PreSharedKey;
    if(!node.AllowedIPs.empty())
        result += ", allowed-ips = \"" + node.AllowedIPs + "\"";
    if(node.KeepAlive > 0)
        result += ", keepalive = " + std::to_string(node.KeepAlive);
    if(!node.ClientId.empty())
    {
        if(client_id_as_reserved)
            result += ", reserved = [" + node.ClientId + "]";
        else
            result += ", client-id = " + node.ClientId;
    }
    return result;
}

std::string proxyToSurge(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, int surge_ver, extra_settings &ext)
{
    INIReader ini;
    std::string output_nodelist;
    std::vector<Proxy> nodelist;
    unsigned short local_port = 1080;
    string_array remarks_list;

    ini.store_any_line = true;
    // filter out sections that requires direct-save
    ini.add_direct_save_section("General");
    ini.add_direct_save_section("Replica");
    ini.add_direct_save_section("Rule");
    ini.add_direct_save_section("MITM");
    ini.add_direct_save_section("Script");
    ini.add_direct_save_section("Host");
    ini.add_direct_save_section("URL Rewrite");
    ini.add_direct_save_section("Header Rewrite");
    if(ini.parse(base_conf) != 0 && !ext.nodelist)
    {
        writeLog(0, "Surge base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    ini.set_current_section("Proxy");
    ini.erase_section();
    ini.set("{NONAME}", "DIRECT = direct");

    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &username = x.Username, &password = x.Password, &method = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &edge = x.Edge, &path = x.Path, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &plugin = x.Plugin, &pluginopts = x.PluginOption, &underlying_proxy = x.UnderlyingProxy;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify, tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        std::string proxy, section, real_section;
        string_array args, headers;

        std::stringstream ss;

        switch (x.Type)
        {
        case ProxyType::Shadowsocks:
            if(surge_ver >= 3 || surge_ver == -3)
            {
                proxy = "ss, " + hostname + ", " + port + ", encrypt-method=" + method + ", password=" + password;
            }
            else
            {
                proxy = "custom, " + hostname + ", " + port + ", " + method + ", " + password + ", https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module";
            }
            if(!plugin.empty())
            {
                switch(hash_(plugin))
                {
                case "simple-obfs"_hash:
                case "obfs-local"_hash:
                    if(!pluginopts.empty())
                        proxy += "," + replaceAllDistinct(pluginopts, ";", ",");
                    break;
                case "shadow-tls"_hash:
                {
                    std::string stls_opts = replaceAllDistinct(pluginopts, ";", "&");
                    std::string stls_pwd = getUrlArg(stls_opts, "password");
                    std::string stls_sni = getUrlArg(stls_opts, "host");
                    if(stls_sni.empty())
                        stls_sni = getUrlArg(stls_opts, "sni");
                    std::string stls_ver = getUrlArg(stls_opts, "version");
                    if(!stls_pwd.empty())
                        proxy += ", shadow-tls-password=" + stls_pwd;
                    if(!stls_sni.empty())
                        proxy += ", shadow-tls-sni=" + stls_sni;
                    if(!stls_ver.empty())
                        proxy += ", shadow-tls-version=" + stls_ver;
                    break;
                }
                default:
                    continue;
                }
            }
            break;
        case ProxyType::VMess:
        {
            if(surge_ver < 3 && surge_ver != -3)
                continue;
            proxy = "vmess, " + hostname + ", " + port + ", username=" + id + ", tls=" + (tlssecure ? "true" : "false") + ", vmess-aead=" + (x.AlterId == 0 ? "true" : "false");
            if(tlssecure)
            {
                std::string vmess_sni = !x.ServerName.empty() ? x.ServerName : (!x.SNI.empty() ? x.SNI : host);
                if(!vmess_sni.empty())
                    proxy += ", sni=" + vmess_sni;
                if(!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                if(!x.Fingerprint.empty())
                    proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
            }
            switch(hash_(transproto))
            {
            case "tcp"_hash:
                break;
            case "ws"_hash:
                proxy += ", ws=true, ws-path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    headers.push_back("Host:" + host);
                if(!edge.empty())
                    headers.push_back("Edge:" + edge);
                if(!headers.empty())
                    proxy += ", ws-headers=" + join(headers, "|");
                break;
            default:
                continue;
            }
            udp = tribool(); // Surge VMess 原生支持 UDP，无需 udp-relay 参数
            break;
        }
        case ProxyType::ShadowsocksR:
            if(ext.surge_ssr_path.empty() || surge_ver < 2)
                continue;
            proxy = "external, exec=\"" + ext.surge_ssr_path + "\", args=\"";
            args = {"-l", std::to_string(local_port), "-s", hostname, "-p", port, "-m", method, "-k", password, "-o", obfs, "-O", protocol};
            if(!obfsparam.empty())
            {
                args.emplace_back("-g");
                args.emplace_back(std::move(obfsparam));
            }
            if(!protoparam.empty())
            {
                args.emplace_back("-G");
                args.emplace_back(std::move(protoparam));
            }
            proxy += join(args, "\", args=\"");
            proxy += "\", local-port=" + std::to_string(local_port);
            if(isIPv4(hostname) || isIPv6(hostname))
                proxy += ", addresses=" + hostname;
            else if(global.surgeResolveHostname)
                proxy += ", addresses=" + hostnameToIPAddr(hostname);
            local_port++;
            break;
        case ProxyType::SOCKS5:
            proxy = "socks5, " + hostname + ", " + port;
            if(!username.empty())
                proxy += ", username=" + username;
            if(!password.empty())
                proxy += ", password=" + password;
            if(!scv.is_undef())
                proxy += ", skip-cert-verify=" + scv.get_str();
            break;
        case ProxyType::HTTPS:
            if(surge_ver == -3)
            {
                proxy = "https, " + hostname + ", " + port + ", " + username + ", " + password;
                if(!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                udp = tribool();
                break;
            }
            [[fallthrough]];
        case ProxyType::HTTP:
            proxy = std::string(x.TLSSecure ? "https, " : "http, ") + hostname + ", " + port;
            if(!username.empty())
                proxy += ", username=" + username;
            if(!password.empty())
                proxy += ", password=" + password;
            if(x.TLSSecure && !scv.is_undef())
                proxy += ", skip-cert-verify=" + scv.get_str();
            udp = tribool();
            break;
        case ProxyType::Trojan:
        {
            if(surge_ver < 3 && surge_ver != -3)
                continue;
            proxy = "trojan, " + hostname + ", " + port + ", password=" + password;
            if(x.SnellVersion != 0)
                proxy += ", version=" + std::to_string(x.SnellVersion);
            std::string trojan_sni = !x.SNI.empty() ? x.SNI : (!x.ServerName.empty() ? x.ServerName : host);
            if(!trojan_sni.empty())
                proxy += ", sni=" + trojan_sni;
            if(!x.Alpn.empty())
            {
                std::string alpn_str = join(x.Alpn, ",");
                if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                    proxy += ", alpn=\"" + alpn_str + "\"";
                else
                    proxy += ", alpn=" + alpn_str;
            }
            if(!scv.is_undef())
                proxy += ", skip-cert-verify=" + scv.get_str();
            if(!x.Fingerprint.empty())
                proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
            switch(hash_(transproto))
            {
            case ""_hash:
            case "tcp"_hash:
                break;
            case "ws"_hash:
                proxy += ", ws=true, ws-path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    headers.push_back("Host:" + host);
                if(!edge.empty())
                    headers.push_back("Edge:" + edge);
                if(!headers.empty())
                    proxy += ", ws-headers=" + join(headers, "|");
                break;
            default:
                continue;
            }
            udp = tribool(); // Surge Trojan 原生支持 UDP，无需 udp-relay 参数
            break;
        }
        case ProxyType::Snell:
            proxy = "snell, " + hostname + ", " + port + ", psk=" + password;
            if(!obfs.empty())
            {
                proxy += ", obfs=" + obfs;
                if(!host.empty())
                    proxy += ", obfs-host=" + host;
            }
            if(x.SnellVersion != 0)
                proxy += ", version=" + std::to_string(x.SnellVersion);
            if(x.SnellVersion >= 3)
                udp = tribool();
            break;
        case ProxyType::WireGuard:
            if(surge_ver < 3 && surge_ver != -3)
                continue;
            ss << std::hex << hash_(x.Remark);
            section = ss.str().substr(0, 5);
            real_section = "WireGuard " + section;
            proxy = "wireguard, section-name=" + section;
            if(!x.TestUrl.empty())
                proxy += ", test-url=" + x.TestUrl;
            ini.set(real_section, "private-key", x.PrivateKey);
            ini.set(real_section, "self-ip", x.SelfIP);
            if(!x.SelfIPv6.empty())
                ini.set(real_section, "self-ip-v6", x.SelfIPv6);
            if(!x.DnsServers.empty())
                ini.set(real_section, "dns-server", join(x.DnsServers, ","));
            if(x.Mtu > 0)
                ini.set(real_section, "mtu", std::to_string(x.Mtu));
            ini.set(real_section, "peer", "(" + generatePeer(x) + ")");
            udp = tribool();
            tfo = tribool();
            break;
        case ProxyType::Hysteria2:
        {
            if(surge_ver < 4)
                continue;
            proxy = "hysteria2, " + hostname + ", " + port + ", password=" + password;
            if(x.DownSpeed > 0)
                proxy += ", download-bandwidth=" + std::to_string(x.DownSpeed);
            if(x.OBFS == "salamander" && !x.OBFSParam.empty())
                proxy += ", salamander-password=" + x.OBFSParam;
            std::string hy2_ports = !x.Mport.empty() ? x.Mport : x.Ports;
            if(!hy2_ports.empty() && hy2_ports != port && underlying_proxy.empty())
            {
                proxy += ", port-hopping=" + replaceAllDistinct(hy2_ports, ",", ";");
                if(x.HopInterval > 0)
                    proxy += ", port-hopping-interval=" + std::to_string(x.HopInterval);
            }
            if(!x.SNI.empty())
                proxy += ", sni=" + x.SNI;
            if(!x.Alpn.empty())
            {
                std::string alpn_str = join(x.Alpn, ",");
                if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                    proxy += ", alpn=\"" + alpn_str + "\"";
                else
                    proxy += ", alpn=" + alpn_str;
            }
            if(!scv.is_undef())
                proxy += ", skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
            udp = tribool(); // Surge Hysteria2 原生支持 UDP
            break;
        }
        case ProxyType::TUIC:
        {
            if(surge_ver < 4)
                continue;
            proxy = "tuic-v5, " + hostname + ", " + port + ", password=" + password;
            if(!x.UUID.empty())
                proxy += ", uuid=" + x.UUID;
            if(!x.SNI.empty())
                proxy += ", sni=" + x.SNI;
            if(!x.Alpn.empty())
            {
                std::string alpn_str = join(x.Alpn, ",");
                if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                    proxy += ", alpn=\"" + alpn_str + "\"";
                else
                    proxy += ", alpn=" + alpn_str;
            }
            if(!scv.is_undef())
                proxy += ", skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
            udp = tribool(); // Surge TUIC 原生支持 UDP
            break;
        }
        case ProxyType::AnyTLS:
        {
            if(surge_ver < 3 && surge_ver != -3)
                continue;
            proxy = "anytls, " + hostname + ", " + port + ", password=" + password;
            if(!x.SNI.empty())
                proxy += ", sni=" + x.SNI;
            if(!x.Alpn.empty())
            {
                std::string alpn_str = join(x.Alpn, ",");
                if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                    proxy += ", alpn=\"" + alpn_str + "\"";
                else
                    proxy += ", alpn=" + alpn_str;
            }
            if(!scv.is_undef())
                proxy += ", skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
            udp = tribool(); // Surge AnyTLS 原生支持 UDP
            break;
        }
        case ProxyType::VLESS:
        {
            if(surge_ver < 3 && surge_ver != -3)
                continue;

            // 1. 过滤 Surge VLESS 明确不支持的 VLESS Encryption 与 HTTPUpgrade
            if(!x.VlessEncryption.empty() && x.VlessEncryption != "none")
                continue;
            if(!x.V2rayHttpUpgrade.is_undef() && x.V2rayHttpUpgrade.get())
                continue;

            std::string vless_uuid = !x.UUID.empty() ? x.UUID : id;
            if(vless_uuid.empty())
                continue;

            bool is_reality = !x.PublicKey.empty();
            bool is_raw_tcp = (transproto.empty() || transproto == "tcp" || transproto == "raw");

            // 2. 校验传输层与安全层的合法组合（参照 Surge Manual Supported combinations 矩阵）
            if(transproto == "ws" && is_reality)
                continue; // Surge VLESS: WebSocket 不支持 REALITY
            if(transproto == "grpc" && !is_reality && !tlssecure)
                continue; // Surge VLESS: gRPC 必须启用 TLS 或 REALITY

            proxy = "vless, " + hostname + ", " + port + ", username=" + vless_uuid;

            // 3. Flow 参数：仅在 RAW(TCP) + (TLS 或 REALITY) 下生效，且仅支持 Vision 流控
            std::string vless_flow = (x.XTLS == 2) ? "xtls-rprx-vision" : x.Flow;
            if(!vless_flow.empty())
            {
                if(!is_raw_tcp || (!is_reality && !tlssecure))
                    continue; // Vision 流控不支持与 WebSocket/gRPC 或无 TLS 的明文 TCP 组合
                if(vless_flow == "xtls-rprx-vision" || vless_flow == "xtls-rprx-vision-udp443")
                    proxy += ", flow=" + vless_flow;
                else
                    continue; // 不支持的旧版流控（如 xtls-rprx-direct）直接跳过
            }

            // 4. 安全性参数：区分 REALITY 与标准 TLS
            if(is_reality)
            {
                // REALITY 模式下 sni 必填（优先取 SNI -> ServerName -> Host -> Hostname）
                std::string reality_sni = !x.SNI.empty() ? x.SNI : (!x.ServerName.empty() ? x.ServerName : (!host.empty() ? host : hostname));
                if(reality_sni.empty())
                    continue;

                proxy += ", reality-public-key=" + x.PublicKey;
                if(!x.ShortID.empty())
                    proxy += ", reality-short-id=" + x.ShortID;
                proxy += ", sni=" + reality_sni;
            }
            else if(tlssecure)
            {
                proxy += ", tls=true";
                std::string tls_sni = !x.SNI.empty() ? x.SNI : x.ServerName;
                if(!tls_sni.empty())
                    proxy += ", sni=" + tls_sni;

                if(!x.Alpn.empty())
                {
                    std::string alpn_str = join(x.Alpn, ",");
                    if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                        proxy += ", alpn=\"" + alpn_str + "\"";
                    else
                        proxy += ", alpn=" + alpn_str;
                }
                if(!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                if(!x.Fingerprint.empty())
                    proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
            }

            // 5. 传输层参数（RAW / WebSocket / gRPC）
            switch(hash_(transproto))
            {
            case ""_hash:
            case "tcp"_hash:
            case "raw"_hash:
                break;
            case "ws"_hash:
                proxy += ", ws=true";
                if(!path.empty())
                    proxy += ", ws-path=" + path;
                if(!host.empty())
                    headers.push_back("Host:" + host);
                if(!edge.empty())
                    headers.push_back("Edge:" + edge);
                if(!headers.empty())
                    proxy += ", ws-headers=" + join(headers, "|");
                break;
            case "grpc"_hash:
            {
                proxy += ", grpc=true";
                std::string grpc_srv = !x.GRPCServiceName.empty() ? urlDecode(x.GRPCServiceName) : path;
                if(!grpc_srv.empty())
                    proxy += ", grpc-service-name=" + grpc_srv;
                if(x.GRPCMode == "multi")
                    proxy += ", grpc-mode=multi";
                if(!host.empty())
                    proxy += ", grpc-authority=" + host;
                break;
            }
            default:
                // 跳过 XHTTP / HTTPUpgrade / mKCP / QUIC / H2 等不支持的传输层
                continue;
            }

            // 6. VLESS 原生支持 XUDP，无需输出 udp-relay 参数，清空 udp 防止尾部追加
            udp = tribool();
            break;
        }
        default:
            continue;
        }

        if(!tfo.is_undef())
            proxy += ", tfo=" + tfo.get_str();
        if(!udp.is_undef())
            proxy += ", udp-relay=" + udp.get_str();

        if (underlying_proxy != "")
            proxy += ", underlying-proxy=" + underlying_proxy;

        if (ext.nodelist)
            output_nodelist += x.Remark + " = " + proxy + "\n";
        else
        {
            ini.set("{NONAME}", x.Remark + " = " + proxy);
            nodelist.emplace_back(x);
        }
        remarks_list.emplace_back(x.Remark);
    }

    if(ext.nodelist)
        return output_nodelist;

    string_multimap original_groups;
    std::string surge_group_section = "Proxy Group";
    if(ini.section_exist("ProxyGroup") && !ini.section_exist("Proxy Group"))
        surge_group_section = "ProxyGroup";
    ini.set_current_section(surge_group_section);
    ini.get_items(original_groups);
    ini.erase_section();
    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string group;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::Smart:
        case ProxyGroupType::URLTest:
        case ProxyGroupType::Fallback:
            break;
        case ProxyGroupType::LoadBalance:
            if(surge_ver < 1 && surge_ver != -3)
                continue;
            break;
        case ProxyGroupType::SSID:
            group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
            group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
            ini.set("{NONAME}", x.Name + " = " + group); //insert order
            continue;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        if(filtered_nodelist.size() == 1)
        {
            group = toLower(filtered_nodelist[0]);
            switch(hash_(group))
            {
            case "direct"_hash:
            case "reject"_hash:
            case "reject-tinygif"_hash:
                ini.set("Proxy", "{NONAME}", x.Name + " = " + group);
                continue;
            }
        }

        group = x.TypeStr() + ",";
        group += join(filtered_nodelist, ",");
        if(x.Type == ProxyGroupType::URLTest || x.Type == ProxyGroupType::Smart || x.Type == ProxyGroupType::Fallback || x.Type == ProxyGroupType::LoadBalance)
        {
            if(!x.Url.empty())
                group += ",url=" + x.Url;
            if(x.Interval > 0)
                group += ",interval=" + std::to_string(x.Interval);
            if(x.Tolerance > 0)
                group += ",tolerance=" + std::to_string(x.Tolerance);
            if(x.Timeout > 0)
                group += ",timeout=" + std::to_string(x.Timeout);
            if(!x.Persistent.is_undef())
                group += ",persistent=" + x.Persistent.get_str();
            if(!x.EvaluateBeforeUse.is_undef())
                group += ",evaluate-before-use=" + x.EvaluateBeforeUse.get_str();
        }

        auto iter = original_groups.find(x.Name);
        if(iter != original_groups.end())
        {
            string_array vArray = split(iter->second, ",");
            if(vArray.size() > 1)
            {
                std::string content = trim(vArray[vArray.size() - 1]);
                if(content.find("icon-url") == 0)
                    group += "," + content;
            }
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, surge_ver, ext.overwrite_original_rules, ext.managed_config_prefix);

    return ini.to_string();
}

std::string proxyToSingle(std::vector<Proxy> &nodes, int types, extra_settings &ext)
{
    /// types: SS=1 SSR=2 VMess=4 Trojan=8
    std::string proxyStr, allLinks;
    bool ss = GETBIT(types, 1), ssr = GETBIT(types, 2), vmess = GETBIT(types, 3), trojan = GETBIT(types, 4);

    for(Proxy &x : nodes)
    {
        std::string remark = x.Remark;
        std::string &hostname = x.Hostname, &password = x.Password, &method = x.EncryptMethod, &plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &faketype = x.FakeType;
        bool &tlssecure = x.TLSSecure;
        std::string port = std::to_string(x.Port);
        std::string aid = std::to_string(x.AlterId);

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(ss)
            {
                proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                if(!plugin.empty() && !pluginopts.empty())
                {
                    proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
                }
                proxyStr += "#" + urlEncode(remark);
            }
            else if(ssr)
            {
                if(std::find(ssr_ciphers.begin(), ssr_ciphers.end(), method) != ssr_ciphers.end() && plugin.empty())
                    proxyStr = "ssr://" + urlSafeBase64Encode(hostname + ":" + port + ":origin:" + method + ":plain:" + urlSafeBase64Encode(password) \
                               + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(remark));
            }
            else
                continue;
            break;
        case ProxyType::ShadowsocksR:
            if(ssr)
            {
                proxyStr = "ssr://" + urlSafeBase64Encode(hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" + urlSafeBase64Encode(password) \
                           + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(remark) \
                           + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" + urlSafeBase64Encode(protoparam));
            }
            else if(ss)
            {
                if(std::find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && protocol == "origin" && obfs == "plain")
                    proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port + "#" + urlEncode(remark);
            }
            else
                continue;
            break;
        case ProxyType::VMess:
            if(!vmess)
                continue;
            proxyStr = "vmess://" + base64Encode(vmessLinkConstruct(remark, hostname, port, faketype, id, aid, transproto, path, host, tlssecure ? "tls" : ""));
            break;
        case ProxyType::Trojan:
        {
            if(!trojan)
                continue;
            proxyStr = "trojan://" + urlEncode(password) + "@" + hostname + ":" + port + "?allowInsecure=" + (x.AllowInsecure.get() ? "1" : "0");
            std::string trojan_sni = !x.SNI.empty() ? x.SNI : (!x.ServerName.empty() ? x.ServerName : host);
            if(!trojan_sni.empty())
                proxyStr += "&sni=" + urlEncode(trojan_sni);
            if(transproto == "ws")
            {
                proxyStr += "&type=ws&ws=1";
                if(!host.empty())
                    proxyStr += "&host=" + urlEncode(host);
                if(!path.empty())
                    proxyStr += "&path=" + urlEncode(path) + "&wspath=" + urlEncode(path);
            }
            else if(transproto == "grpc")
            {
                proxyStr += "&type=grpc";
                std::string grpc_srv = !x.GRPCServiceName.empty() ? urlDecode(x.GRPCServiceName) : path;
                if(!grpc_srv.empty())
                    proxyStr += "&serviceName=" + urlEncode(grpc_srv);
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        }
        case ProxyType::VLESS:
        {
            if(!vmess && types > 0)
                continue;
            std::string vless_uuid = !x.UUID.empty() ? x.UUID : id;
            if(vless_uuid.empty())
                continue;
            std::string vless_net = transproto.empty() ? "tcp" : transproto;
            proxyStr = "vless://" + urlEncode(vless_uuid) + "@" + hostname + ":" + port + "?encryption=" + (x.VlessEncryption.empty() ? "none" : urlEncode(x.VlessEncryption)) + "&type=" + vless_net;
            if(!x.PublicKey.empty())
            {
                proxyStr += "&security=reality&pbk=" + urlEncode(x.PublicKey);
                if(!x.ShortID.empty())
                    proxyStr += "&sid=" + urlEncode(x.ShortID);
            }
            else if(tlssecure)
            {
                proxyStr += "&security=tls";
                if(!x.AllowInsecure.is_undef())
                    proxyStr += std::string("&allowInsecure=") + (x.AllowInsecure.get() ? "1" : "0");
            }
            else
            {
                proxyStr += "&security=none";
            }
            std::string vless_sni = !x.SNI.empty() ? x.SNI : (!x.ServerName.empty() ? x.ServerName : "");
            if(!vless_sni.empty())
                proxyStr += "&sni=" + urlEncode(vless_sni);
            std::string vless_flow = (x.XTLS == 2) ? "xtls-rprx-vision" : x.Flow;
            if(!vless_flow.empty())
                proxyStr += "&flow=" + urlEncode(vless_flow);
            if(!x.ClientFingerprint.empty())
                proxyStr += "&fp=" + urlEncode(x.ClientFingerprint);
            if(!x.Alpn.empty())
                proxyStr += "&alpn=" + urlEncode(join(x.Alpn, ","));
            if(vless_net == "ws" || vless_net == "http" || vless_net == "h2")
            {
                if(!host.empty())
                    proxyStr += "&host=" + urlEncode(host);
                if(!path.empty())
                    proxyStr += "&path=" + urlEncode(path);
            }
            else if(vless_net == "grpc")
            {
                std::string grpc_srv = !x.GRPCServiceName.empty() ? urlDecode(x.GRPCServiceName) : path;
                if(!grpc_srv.empty())
                    proxyStr += "&serviceName=" + urlEncode(grpc_srv);
                if(!x.GRPCMode.empty())
                    proxyStr += "&mode=" + urlEncode(x.GRPCMode);
                if(!host.empty())
                    proxyStr += "&authority=" + urlEncode(host);
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        }
        case ProxyType::Hysteria2:
        {
            if(types > 0 && !trojan && !vmess)
                continue;
            proxyStr = "hysteria2://" + urlEncode(password) + "@" + hostname + ":" + port + "/?insecure=" + (x.AllowInsecure.get() ? "1" : "0");
            if(!x.SNI.empty())
                proxyStr += "&sni=" + urlEncode(x.SNI);
            if(x.OBFS == "salamander" && !x.OBFSParam.empty())
                proxyStr += "&obfs=salamander&obfs-password=" + urlEncode(x.OBFSParam);
            std::string hy2_ports = !x.Mport.empty() ? x.Mport : x.Ports;
            if(!hy2_ports.empty())
                proxyStr += "&mport=" + urlEncode(hy2_ports);
            if(!x.Alpn.empty())
                proxyStr += "&alpn=" + urlEncode(join(x.Alpn, ","));
            if(!x.Fingerprint.empty())
                proxyStr += "&pinSHA256=" + urlEncode(x.Fingerprint);
            proxyStr += "#" + urlEncode(remark);
            break;
        }
        case ProxyType::TUIC:
        {
            if(types > 0 && !trojan && !vmess)
                continue;
            proxyStr = "tuic://" + urlEncode(x.UUID) + ":" + urlEncode(password) + "@" + hostname + ":" + port + "/?insecure=" + (x.AllowInsecure.get() ? "1" : "0");
            if(!x.SNI.empty())
                proxyStr += "&sni=" + urlEncode(x.SNI);
            if(!x.Alpn.empty())
                proxyStr += "&alpn=" + urlEncode(join(x.Alpn, ","));
            if(!x.CongestionController.empty())
                proxyStr += "&congestion_control=" + urlEncode(x.CongestionController);
            if(!x.UdpRelayMode.empty())
                proxyStr += "&udp_relay_mode=" + urlEncode(x.UdpRelayMode);
            proxyStr += "#" + urlEncode(remark);
            break;
        }
        case ProxyType::AnyTLS:
        {
            if(types > 0 && !trojan && !vmess)
                continue;
            proxyStr = "anytls://" + urlEncode(password) + "@" + hostname + ":" + port + "/?insecure=" + (x.AllowInsecure.get() ? "1" : "0");
            if(!x.SNI.empty())
                proxyStr += "&sni=" + urlEncode(x.SNI);
            if(!x.Alpn.empty())
                proxyStr += "&alpn=" + urlEncode(join(x.Alpn, ","));
            if(!x.Fingerprint.empty())
                proxyStr += "&hpkp=" + urlEncode(x.Fingerprint);
            proxyStr += "#" + urlEncode(remark);
            break;
        }
        default:
            continue;
        }
        allLinks += proxyStr + "\n";
    }

    if(ext.nodelist)
        return allLinks;
    else
        return base64Encode(allLinks);
}

std::string proxyToSSSub(std::string base_conf, std::vector<Proxy> &nodes, extra_settings &ext)
{
    using namespace rapidjson_ext;
    rapidjson::Document base;

    auto &alloc = base.GetAllocator();

    base_conf = trimWhitespace(base_conf);
    if(base_conf.empty())
        base_conf = "{}";
    rapidjson::ParseResult result = base.Parse(base_conf.data());
    if (!result)
        writeLog(0, std::string("SIP008 base loader failed with error: ") + rapidjson::GetParseError_En(result.Code()) + " (" + std::to_string(result.Offset()) + ")", LOG_LEVEL_ERROR);

    rapidjson::Value proxies(rapidjson::kArrayType);
    for(Proxy &x : nodes)
    {
        std::string &remark = x.Remark;
        std::string &hostname = x.Hostname;
        std::string &password = x.Password;
        std::string &method = x.EncryptMethod;
        std::string &plugin = x.Plugin;
        std::string &pluginopts = x.PluginOption;
        std::string &protocol = x.Protocol;
        std::string &obfs = x.OBFS;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(plugin == "simple-obfs")
                plugin = "obfs-local";
            break;
        case ProxyType::ShadowsocksR:
            if(std::find(ss_ciphers.begin(), ss_ciphers.end(), method) == ss_ciphers.end() || protocol != "origin" || obfs != "plain")
                continue;
            break;
        default:
            continue;
        }
        rapidjson::Value proxy(rapidjson::kObjectType);
        proxy.CopyFrom(base, alloc)
        | AddMemberOrReplace("remarks", rapidjson::Value(remark.c_str(), remark.size()), alloc)
        | AddMemberOrReplace("server", rapidjson::Value(hostname.c_str(), hostname.size()), alloc)
        | AddMemberOrReplace("server_port", rapidjson::Value(x.Port), alloc)
        | AddMemberOrReplace("method", rapidjson::Value(method.c_str(), method.size()), alloc)
        | AddMemberOrReplace("password", rapidjson::Value(password.c_str(), password.size()), alloc)
        | AddMemberOrReplace("plugin", rapidjson::Value(plugin.c_str(), plugin.size()), alloc)
        | AddMemberOrReplace("plugin_opts", rapidjson::Value(pluginopts.c_str(), pluginopts.size()), alloc);
        proxies.PushBack(proxy, alloc);
    }
    return proxies | SerializeObject();
}

std::string proxyToQuan(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    ini.store_any_line = true;
    if(!ext.nodelist && ini.parse(base_conf) != 0)
    {
        writeLog(0, "Quantumult base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuan(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if(ext.nodelist)
    {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("SERVER", "{NONAME}", allnodes);
        if(!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return base64Encode(allLinks);
    }
    return ini.to_string();
}

void proxyToQuan(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    std::string proxyStr;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("SERVER");
    ini.erase_section();
    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &password = x.Password, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &edge = x.Edge, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &plugin = x.Plugin, &pluginopts = x.PluginOption, &username = x.Username;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;
        tribool scv;

        switch(x.Type)
        {
        case ProxyType::VMess:
            scv = ext.skip_cert_verify;
            scv.define(x.AllowInsecure);

            if(method == "auto")
                method = "chacha20-ietf-poly1305";
            proxyStr = x.Remark + " = vmess, " + hostname + ", " + port + ", " + method + ", \"" + id + "\", group=" + x.Group;
            if(tlssecure)
            {
                proxyStr += ", over-tls=true, tls-host=" + host;
                if(!scv.is_undef())
                    proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
            }
            if(transproto == "ws")
            {
                proxyStr += ", obfs=ws, obfs-path=\"" + path + "\", obfs-header=\"Host: " + host;
                if(!edge.empty())
                    proxyStr += "[Rr][Nn]Edge: " + edge;
                proxyStr += "\"";
            }

            if(ext.nodelist)
                proxyStr = "vmess://" + urlSafeBase64Encode(proxyStr);
            break;
        case ProxyType::ShadowsocksR:
            if(ext.nodelist)
            {
                proxyStr = "ssr://" + urlSafeBase64Encode(hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" + urlSafeBase64Encode(password) \
                           + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(x.Remark) \
                           + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" + urlSafeBase64Encode(protoparam));
            }
            else
            {
                proxyStr = x.Remark + " = shadowsocksr, " + hostname + ", " + port + ", " + method + ", \"" + password + "\", group=" + x.Group + ", protocol=" + protocol + ", obfs=" + obfs;
                if(!protoparam.empty())
                    proxyStr += ", protocol_param=" + protoparam;
                if(!obfsparam.empty())
                    proxyStr += ", obfs_param=" + obfsparam;
            }
            break;
        case ProxyType::Shadowsocks:
            if(ext.nodelist)
            {
                proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                if(!plugin.empty() && !pluginopts.empty())
                {
                    proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
                }
                proxyStr += "&group=" + urlSafeBase64Encode(x.Group) + "#" + urlEncode(x.Remark);
            }
            else
            {
                proxyStr = x.Remark + " = shadowsocks, " + hostname + ", " + port + ", " + method + ", \"" + password + "\", group=" + x.Group;
                if(plugin == "obfs-local" && !pluginopts.empty())
                {
                    proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                }
            }
            break;
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            proxyStr = x.Remark + " = http, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port + ", group=" + x.Group;
            if(!username.empty() && !password.empty())
                proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username + ", upstream-proxy-password=" + password;
            else
                proxyStr += ", upstream-proxy-auth=false";

            if(tlssecure)
            {
                proxyStr += ", over-tls=true";
                if(!host.empty())
                    proxyStr += ", tls-host=" + host;
                if(!scv.is_undef())
                    proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
            }

            if(ext.nodelist)
                proxyStr = "http://" + urlSafeBase64Encode(proxyStr);
            break;
        case ProxyType::SOCKS5:
            proxyStr = x.Remark + " = socks, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port + ", group=" + x.Group;
            if(!username.empty() && !password.empty())
                proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username + ", upstream-proxy-password=" + password;
            else
                proxyStr += ", upstream-proxy-auth=false";

            if(tlssecure)
            {
                proxyStr += ", over-tls=true";
                if(!host.empty())
                    proxyStr += ", tls-host=" + host;
                if(!scv.is_undef())
                    proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
            }

            if(ext.nodelist)
                proxyStr = "socks://" + urlSafeBase64Encode(proxyStr);
            break;
        default:
            continue;
        }

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if(ext.nodelist)
        return;

    ini.set_current_section("POLICY");
    ini.erase_section();

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string type;
        std::string singlegroup;
        std::string name, proxies;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::Fallback:
            type = "static";
            break;
        case ProxyGroupType::URLTest:
            type = "auto";
            break;
        case ProxyGroupType::LoadBalance:
            type = "balance, round-robin";
            break;
        case ProxyGroupType::SSID:
            {
                singlegroup = x.Name + " : wifi = " + x.Proxies[0];
                std::string content, celluar, celluar_matcher = R"(^(.*?),?celluar\s?=\s?(.*?)(,.*)$)", rem_a, rem_b;
                for(auto iter = x.Proxies.begin() + 1; iter != x.Proxies.end(); iter++)
                {
                    if(regGetMatch(*iter, celluar_matcher, 4, 0, &rem_a, &celluar, &rem_b))
                    {
                        content += *iter + "\n";
                        continue;
                    }
                    content += rem_a + rem_b + "\n";
                }
                if(!celluar.empty())
                    singlegroup += ", celluar = " + celluar;
                singlegroup += "\n" + replaceAllDistinct(trimOf(content, ','), ",", "\n");
                ini.set("{NONAME}", base64Encode(singlegroup)); //insert order
            }
            continue;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(filtered_nodelist.empty())
            filtered_nodelist.emplace_back("direct");

        if(filtered_nodelist.size() < 2) // force groups with 1 node to be static
            type = "static";

        proxies = join(filtered_nodelist, "\n");

        singlegroup = x.Name + " : " + type;
        if(type == "static")
            singlegroup += ", " + filtered_nodelist[0];
        singlegroup += "\n" + proxies + "\n";
        ini.set("{NONAME}", base64Encode(singlegroup));
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -2, ext.overwrite_original_rules, "");
}

std::string proxyToQuanX(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    ini.store_any_line = true;
    ini.add_direct_save_section("general");
    ini.add_direct_save_section("dns");
    ini.add_direct_save_section("rewrite_remote");
    ini.add_direct_save_section("rewrite_local");
    ini.add_direct_save_section("task_local");
    ini.add_direct_save_section("mitm");
    ini.add_direct_save_section("server_remote");
    if(!ext.nodelist && ini.parse(base_conf) != 0)
    {
        writeLog(0, "QuantumultX base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuanX(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if(ext.nodelist)
    {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("server_local", "{NONAME}", allnodes);
        if(!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return allLinks;
    }
    return ini.to_string();
}

void proxyToQuanX(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    std::string proxyStr;
    tribool udp, tfo, scv, tls13;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("server_local");
    ini.erase_section();
    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &password = x.Password, &plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &username = x.Username, &uuid = x.UUID, &sni = x.SNI, &publickey = x.PublicKey, &shortid = x.ShortID, &flow = x.Flow;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;

        udp = ext.udp;
        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        bool is_reality = !publickey.empty();
        if(is_reality)
            tfo = tribool(); // Quantumult X v1.6.0+: Reality ClientHello with post-quantum X25519MLKEM768 > 1500B, TFO must not be enabled

        switch(x.Type)
        {
        case ProxyType::VMess:
            if(method == "auto")
                method = "chacha20-poly1305";
            proxyStr = "vmess = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
            if(x.AlterId != 0)
                proxyStr += ", aead=false";
            if(tlssecure || is_reality)
            {
                if(transproto == "ws")
                {
                    proxyStr += ", obfs=wss";
                    if(!host.empty())
                        proxyStr += ", obfs-host=" + host;
                    else if(!sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    if(!path.empty())
                        proxyStr += ", obfs-uri=" + path;
                }
                else
                {
                    proxyStr += ", obfs=over-tls";
                    if(!sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    else if(!host.empty())
                        proxyStr += ", obfs-host=" + host;
                }
                if(is_reality)
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
                else
                {
                    if(!x.Fingerprint.empty())
                        proxyStr += ", tls-cert-sha256=" + x.Fingerprint;
                    if(!scv.is_undef())
                        proxyStr += ", tls-verification=" + std::string(scv.get() ? "false" : "true");
                }
                if(tls13.get() && !is_reality)
                    proxyStr += ", tls13=true";
            }
            else
            {
                if(transproto == "ws")
                    proxyStr += ", obfs=ws, obfs-host=" + host + ", obfs-uri=" + path;
                else if(transproto == "http")
                    proxyStr += ", obfs=http, obfs-host=" + host + ", obfs-uri=" + path;
            }
            break;
        case ProxyType::VLESS:
        {
            if(!x.VlessEncryption.empty() && x.VlessEncryption != "none")
                continue;
            std::string vless_uuid = !uuid.empty() ? uuid : id;
            if(vless_uuid.empty())
                continue;
            proxyStr = "vless = " + hostname + ":" + port + ", method=none, password=" + vless_uuid;
            if(tlssecure || is_reality || !flow.empty())
            {
                if(transproto == "ws")
                {
                    proxyStr += ", obfs=wss";
                    if(!host.empty())
                        proxyStr += ", obfs-host=" + host;
                    else if(!sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    if(!path.empty())
                        proxyStr += ", obfs-uri=" + path;
                }
                else if(transproto == "tcp" || transproto == "raw" || transproto.empty())
                {
                    proxyStr += ", obfs=over-tls";
                    if(!sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    else if(!host.empty())
                        proxyStr += ", obfs-host=" + host;
                }
                else
                    continue;

                if(!flow.empty() && (transproto == "tcp" || transproto == "raw" || transproto.empty()))
                    proxyStr += ", vless-flow=" + flow;

                if(is_reality)
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
                else
                {
                    if(!x.Fingerprint.empty())
                        proxyStr += ", tls-cert-sha256=" + x.Fingerprint;
                    if(!scv.is_undef())
                        proxyStr += ", tls-verification=" + std::string(scv.get() ? "false" : "true");
                }
            }
            else
            {
                if(transproto == "ws")
                    proxyStr += ", obfs=ws, obfs-host=" + host + ", obfs-uri=" + path;
                else if(transproto == "http")
                    proxyStr += ", obfs=http, obfs-host=" + host + ", obfs-uri=" + path;
                else if(transproto != "tcp" && transproto != "raw" && !transproto.empty())
                    continue;
            }
            break;
        }
        case ProxyType::Shadowsocks:
            proxyStr = "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password;
            if(!plugin.empty())
            {
                switch(hash_(plugin))
                {
                case "simple-obfs"_hash:
                case "obfs-local"_hash:
                    if(!pluginopts.empty())
                        proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                    break;
                case "v2ray-plugin"_hash:
                    pluginopts = replaceAllDistinct(pluginopts, ";", "&");
                    plugin = getUrlArg(pluginopts, "mode") == "websocket" ? "ws" : "";
                    host = getUrlArg(pluginopts, "host");
                    path = getUrlArg(pluginopts, "path");
                    tlssecure = pluginopts.find("tls") != pluginopts.npos;
                    if(tlssecure && plugin == "ws")
                    {
                        plugin += 's';
                        if(tls13.get() && !is_reality)
                            proxyStr += ", tls13=true";
                    }
                    proxyStr += ", obfs=" + plugin;
                    if(!host.empty())
                        proxyStr += ", obfs-host=" + host;
                    if(!path.empty())
                        proxyStr += ", obfs-uri=" + path;
                    if(tlssecure && is_reality)
                    {
                        proxyStr += ", reality-base64-pubkey=" + publickey;
                        if(!shortid.empty())
                            proxyStr += ", reality-hex-shortid=" + shortid;
                    }
                    break;
                default:
                    continue;
                }
            }
            else if(tlssecure || is_reality)
            {
                proxyStr += ", obfs=over-tls";
                if(!sni.empty())
                    proxyStr += ", obfs-host=" + sni;
                else if(!host.empty())
                    proxyStr += ", obfs-host=" + host;
                if(is_reality)
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
                else if(!x.Fingerprint.empty())
                    proxyStr += ", tls-cert-sha256=" + x.Fingerprint;
            }
            if(!x.UdpOverTcp.is_undef() && x.UdpOverTcp.get())
                proxyStr += ", udp-over-tcp=true";
            break;
        case ProxyType::ShadowsocksR:
            proxyStr = "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password + ", ssr-protocol=" + protocol;
            if(!protoparam.empty())
                proxyStr += ", ssr-protocol-param=" + protoparam;
            proxyStr += ", obfs=" + obfs;
            if(!obfsparam.empty())
                proxyStr += ", obfs-host=" + obfsparam;
            break;
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            proxyStr = "http = " + hostname + ":" + port + ", username=" + (username.empty() ? "none" : username) + ", password=" + (password.empty() ? "none" : password);
            if(tlssecure || is_reality)
            {
                proxyStr += ", over-tls=true";
                if(!sni.empty())
                    proxyStr += ", tls-host=" + sni;
                else if(!host.empty())
                    proxyStr += ", tls-host=" + host;
                if(is_reality)
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
                else
                {
                    if(!x.Fingerprint.empty())
                        proxyStr += ", tls-cert-sha256=" + x.Fingerprint;
                    if(!scv.is_undef())
                        proxyStr += ", tls-verification=" + std::string(scv.get() ? "false" : "true");
                }
                if(tls13.get() && !is_reality)
                    proxyStr += ", tls13=true";
            }
            else
                proxyStr += ", over-tls=false";
            break;
        case ProxyType::Trojan:
            proxyStr = "trojan = " + hostname + ":" + port + ", password=" + password;
            if(tlssecure || is_reality)
            {
                if(transproto == "ws")
                {
                    proxyStr += ", obfs=wss";
                    if(!host.empty())
                        proxyStr += ", obfs-host=" + host;
                    else if(!sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    if(!path.empty())
                        proxyStr += ", obfs-uri=" + path;
                }
                else
                {
                    proxyStr += ", over-tls=true";
                    if(!sni.empty())
                        proxyStr += ", tls-host=" + sni;
                    else if(!host.empty())
                        proxyStr += ", tls-host=" + host;
                }
                if(is_reality)
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
                else
                {
                    if(!x.Fingerprint.empty())
                        proxyStr += ", tls-cert-sha256=" + x.Fingerprint;
                    if(!scv.is_undef())
                        proxyStr += ", tls-verification=" + std::string(scv.get() ? "false" : "true");
                }
                if(tls13.get() && !is_reality)
                    proxyStr += ", tls13=true";
            }
            else
            {
                if(transproto == "ws")
                    proxyStr += ", obfs=ws, obfs-host=" + host + ", obfs-uri=" + path;
                else
                    proxyStr += ", over-tls=false";
            }
            break;
        case ProxyType::AnyTLS:
            proxyStr = "anytls = " + hostname + ":" + port + ", password=" + password + ", over-tls=true";
            if(!sni.empty())
                proxyStr += ", tls-host=" + sni;
            else if(!host.empty())
                proxyStr += ", tls-host=" + host;
            if(is_reality)
            {
                proxyStr += ", reality-base64-pubkey=" + publickey;
                if(!shortid.empty())
                    proxyStr += ", reality-hex-shortid=" + shortid;
            }
            else
            {
                if(!x.Fingerprint.empty())
                    proxyStr += ", tls-cert-sha256=" + x.Fingerprint;
                if(!scv.is_undef())
                    proxyStr += ", tls-verification=" + std::string(scv.get() ? "false" : "true");
            }
            break;
        case ProxyType::SOCKS5:
            proxyStr = "socks5 = " + hostname + ":" + port;
            if(!username.empty() && !password.empty())
            {
                proxyStr += ", username=" + username + ", password=" + password;
                if(tlssecure || is_reality)
                {
                    proxyStr += ", over-tls=true";
                    if(!sni.empty())
                        proxyStr += ", tls-host=" + sni;
                    else if(!host.empty())
                        proxyStr += ", tls-host=" + host;
                    if(is_reality)
                    {
                        proxyStr += ", reality-base64-pubkey=" + publickey;
                        if(!shortid.empty())
                            proxyStr += ", reality-hex-shortid=" + shortid;
                    }
                    else
                    {
                        if(!x.Fingerprint.empty())
                            proxyStr += ", tls-cert-sha256=" + x.Fingerprint;
                        if(!scv.is_undef())
                            proxyStr += ", tls-verification=" + std::string(scv.get() ? "false" : "true");
                    }
                }
            }
            break;
        default:
            continue;
        }
        if(!tfo.is_undef())
            proxyStr += ", fast-open=" + tfo.get_str();
        if(!udp.is_undef())
            proxyStr += ", udp-relay=" + udp.get_str();
        proxyStr += ", tag=" + x.Remark;

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if(ext.nodelist)
        return;

    string_multimap original_groups;
    ini.set_current_section("policy");
    ini.get_items(original_groups);
    ini.erase_section();

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        std::string type;
        string_array filtered_nodelist;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
            type = "static";
            break;
        case ProxyGroupType::URLTest:
        case ProxyGroupType::Smart:
            type = "url-latency-benchmark";
            break;
        case ProxyGroupType::Fallback:
            type = "available";
            break;
        case ProxyGroupType::LoadBalance:
            type = "round-robin";
            break;
        case ProxyGroupType::SSID:
            type = "ssid";
            for(const auto &proxy : x.Proxies)
                filtered_nodelist.emplace_back(replaceAllDistinct(proxy, "=", ":"));
            break;
        default:
            continue;
        }

        if(x.Type != ProxyGroupType::SSID)
        {
            for(const auto &y : x.Proxies)
                groupGenerate(y, nodelist, filtered_nodelist, true, ext);

            if(filtered_nodelist.empty())
                filtered_nodelist.emplace_back("direct");

            if(filtered_nodelist.size() < 2) // force groups with 1 node to be static
                type = "static";
        }

        auto iter = std::find_if(original_groups.begin(), original_groups.end(), [&](const string_multimap::value_type &n)
        {
            std::string groupdata = n.second;
            std::string::size_type cpos = groupdata.find(',');
            if(cpos != std::string::npos)
                return trim(groupdata.substr(0, cpos)) == x.Name;
            else
                return false;
        });
        if(iter != original_groups.end())
        {
            string_array vArray = split(iter->second, ",");
            if(vArray.size() > 1)
            {
                if(trim(vArray[vArray.size() - 1]).find("img-url") == 0)
                    filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
            }
        }

        std::string proxies = join(filtered_nodelist, ", ");

        std::string singlegroup = type + "=" + x.Name + ", " + proxies;
        if(x.Type != ProxyGroupType::Select && x.Type != ProxyGroupType::SSID)
        {
            singlegroup += ", check-interval=" + std::to_string(x.Interval);
            if(x.Tolerance > 0)
                singlegroup += ", tolerance=" + std::to_string(x.Tolerance);
        }
        ini.set("{NONAME}", singlegroup);
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -1, ext.overwrite_original_rules, ext.managed_config_prefix);
}

std::string proxyToSSD(std::vector<Proxy> &nodes, std::string &group, std::string &userinfo, extra_settings &ext)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    int index = 0;

    if(group.empty())
        group = "SSD";

    writer.StartObject();
    writer.Key("airport");
    writer.String(group.data());
    writer.Key("port");
    writer.Int(1);
    writer.Key("encryption");
    writer.String("aes-128-gcm");
    writer.Key("password");
    writer.String("password");
    if(!userinfo.empty())
    {
        std::string data = replaceAllDistinct(userinfo, "; ", "&");
        std::string upload = getUrlArg(data, "upload"), download = getUrlArg(data, "download"), total = getUrlArg(data, "total"), expiry = getUrlArg(data, "expire");
        double used = (to_number(upload, 0.0) + to_number(download, 0.0)) / std::pow(1024, 3) * 1.0, tot = to_number(total, 0.0) / std::pow(1024, 3) * 1.0;
        writer.Key("traffic_used");
        writer.Double(used);
        writer.Key("traffic_total");
        writer.Double(tot);
        if(!expiry.empty())
        {
            const time_t rawtime = to_int(expiry);
            char buffer[30];
            struct tm *dt = localtime(&rawtime);
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", dt);
            writer.Key("expiry");
            writer.String(buffer);
        }
    }
    writer.Key("servers");
    writer.StartArray();

    for(Proxy &x : nodes)
    {
        std::string &hostname = x.Hostname, &password = x.Password, &method = x.EncryptMethod, &plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &obfs = x.OBFS;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(plugin == "obfs-local")
                plugin = "simple-obfs";
            writer.StartObject();
            writer.Key("server");
            writer.String(hostname.data());
            writer.Key("port");
            writer.Int(x.Port);
            writer.Key("encryption");
            writer.String(method.data());
            writer.Key("password");
            writer.String(password.data());
            writer.Key("plugin");
            writer.String(plugin.data());
            writer.Key("plugin_options");
            writer.String(pluginopts.data());
            writer.Key("remarks");
            writer.String(x.Remark.data());
            writer.Key("id");
            writer.Int(index);
            writer.EndObject();
            break;
        case ProxyType::ShadowsocksR:
            if(std::count(ss_ciphers.begin(), ss_ciphers.end(), method) > 0 && protocol == "origin" && obfs == "plain")
            {
                writer.StartObject();
                writer.Key("server");
                writer.String(hostname.data());
                writer.Key("port");
                writer.Int(x.Port);
                writer.Key("encryption");
                writer.String(method.data());
                writer.Key("password");
                writer.String(password.data());
                writer.Key("remarks");
                writer.String(x.Remark.data());
                writer.Key("id");
                writer.Int(index);
                writer.EndObject();
                break;
            }
            else
                continue;
        default:
            continue;
        }
        index++;
    }
    writer.EndArray();
    writer.EndObject();
    return "ssd://" + base64Encode(sb.GetString());
}

std::string proxyToMellow(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    ini.store_any_line = true;
    if(ini.parse(base_conf) != 0)
    {
        writeLog(0, "Mellow base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToMellow(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    return ini.to_string();
}

void proxyToMellow(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    std::string proxy;
    std::string username, password, method;
    std::string plugin, pluginopts;
    std::string id, aid, transproto, faketype, host, path, quicsecure, quicsecret, tlssecure;
    std::string url;
    tribool tfo, scv;
    std::vector<Proxy> nodelist;
    string_array vArray, remarks_list;

    ini.set_current_section("Endpoint");

    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, port = std::to_string(x.Port);
        username = x.Username;
        password = x.Password;
        method = x.EncryptMethod;
        plugin = x.Plugin;
        pluginopts = x.PluginOption;
        id = x.UserId;
        aid = std::to_string(x.AlterId);
        transproto = x.TransferProtocol;
        faketype = x.FakeType;
        host = !x.Host.empty() ? x.Host : (!x.ServerName.empty() ? x.ServerName : x.SNI);
        path = x.Path;
        quicsecure = x.QUICSecure;
        quicsecret = x.QUICSecret;
        tlssecure = x.TLSSecure ? "true" : "false";

        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(!x.Plugin.empty())
                continue;
            proxy = x.Remark + ", ss, ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
            break;
        case ProxyType::VMess:
            proxy = x.Remark + ", vmess1, vmess1://" + id + "@" + hostname + ":" + port;
            if(!path.empty())
                proxy += path;
            proxy += "?network=" + transproto;
            switch(hash_(transproto))
            {
            case "ws"_hash:
                proxy += "&ws.host=" + urlEncode(host);
                break;
            case "http"_hash:
                if(!host.empty())
                    proxy += "&http.host=" + urlEncode(host);
                break;
            case "quic"_hash:
                if(!quicsecure.empty())
                    proxy += "&quic.security=" + quicsecure + "&quic.key=" + quicsecret;
                break;
            case "kcp"_hash:
            case "tcp"_hash:
                break;
            }
            proxy += "&tls=" + tlssecure;
            if(tlssecure == "true")
            {
                if(!host.empty())
                    proxy += "&tls.servername=" + urlEncode(host);
            }
            if(!scv.is_undef())
                proxy += "&tls.allowinsecure=" + scv.get_str();
            if(!tfo.is_undef())
                proxy += "&sockopt.tcpfastopen=" + tfo.get_str();
            break;
        case ProxyType::SOCKS5:
            proxy = x.Remark + ", builtin, socks, address=" + hostname + ", port=" + port + ", user=" + username + ", pass=" + password;
            break;
        case ProxyType::HTTP:
            proxy = x.Remark + ", builtin, http, address=" + hostname + ", port=" + port + ", user=" + username + ", pass=" + password;
            break;
        default:
            continue;
        }

        ini.set("{NONAME}", proxy);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    ini.set_current_section("EndpointGroup");

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        url.clear();
        proxy.clear();

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::URLTest:
        case ProxyGroupType::Fallback:
        case ProxyGroupType::LoadBalance:
            break;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, false, ext);

        if(filtered_nodelist.empty())
        {
            if(remarks_list.empty())
                filtered_nodelist.emplace_back("DIRECT");
            else
                filtered_nodelist = remarks_list;
        }

        proxy = x.Name + ", ";
        proxy += join(filtered_nodelist, ":");
        proxy += ", latency, interval=300, timeout=6"; //use hard-coded values for now

        ini.set("{NONAME}", proxy); //insert order
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, 0, ext.overwrite_original_rules, "");
}

std::string proxyToLoon(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    std::string output_nodelist;
    std::vector<Proxy> nodelist;

    string_array remarks_list;

    ini.store_any_line = true;
    ini.add_direct_save_section("General");
    ini.add_direct_save_section("DNS");
    ini.add_direct_save_section("Host");
    ini.add_direct_save_section("Rule");
    ini.add_direct_save_section("Remote Proxy");
    ini.add_direct_save_section("Remote Rule");
    ini.add_direct_save_section("Remote Filter");
    ini.add_direct_save_section("Proxy Chain");
    ini.add_direct_save_section("Rewrite");
    ini.add_direct_save_section("URL Rewrite");
    ini.add_direct_save_section("Header Rewrite");
    ini.add_direct_save_section("Body Rewrite");
    ini.add_direct_save_section("Script");
    ini.add_direct_save_section("Plugin");
    ini.add_direct_save_section("MITM");
    ini.add_direct_save_section("MitM");
    ini.add_direct_save_section("Mitm");
    if(ini.parse(base_conf) != INIREADER_EXCEPTION_NONE && !ext.nodelist)
    {
        writeLog(0, "Loon base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    ini.set_current_section("Proxy");
    ini.erase_section();

    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }
        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &username = x.Username, &password = x.Password, &method = x.EncryptMethod, &plugin = x.Plugin, &pluginopts = x.PluginOption, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam;
        std::string port = std::to_string(x.Port), aid = std::to_string(x.AlterId);
        bool &tlssecure = x.TLSSecure;

        tribool scv = ext.skip_cert_verify, udp = ext.udp, tfo = ext.tfo;
        scv.define(x.AllowInsecure);
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);

        std::string proxy;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            proxy = "Shadowsocks," + hostname + "," + port + "," + method + ",\"" + password + "\"";
            if(plugin == "simple-obfs" || plugin == "obfs-local")
            {
                if(!pluginopts.empty())
                    proxy += "," + replaceAllDistinct(replaceAllDistinct(pluginopts, ";obfs-host=", ",obfs-host="), "obfs=", "obfs-name=");
            }
            else if(plugin == "shadow-tls")
            {
                std::string stls_opts = replaceAllDistinct(pluginopts, ";", "&");
                std::string stls_pwd = getUrlArg(stls_opts, "password");
                std::string stls_sni = getUrlArg(stls_opts, "host");
                if(stls_sni.empty())
                    stls_sni = getUrlArg(stls_opts, "sni");
                std::string stls_ver = getUrlArg(stls_opts, "version");
                if(!stls_pwd.empty())
                    proxy += ",shadow-tls-password=\"" + stls_pwd + "\"";
                if(!stls_sni.empty())
                    proxy += ",shadow-tls-sni=" + stls_sni;
                if(!stls_ver.empty())
                    proxy += ",shadow-tls-version=" + stls_ver;
            }
            else if(!plugin.empty())
                continue;
            if(!x.UdpOverTcp.is_undef() && x.UdpOverTcp.get())
                proxy += ",udp-over-tcp=true";
            break;
        case ProxyType::VMess:
        {
            if(method == "auto")
                method = "chacha20-ietf-poly1305";

            proxy = "VMess," + hostname + "," + port + "," + method + ",\"" + id + "\"";
            switch(hash_(transproto))
            {
            case ""_hash:
            case "tcp"_hash:
                proxy += ",transport=tcp";
                break;
            case "ws"_hash:
                proxy += ",transport=ws,path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    proxy += ",host=" + host;
                break;
            case "http"_hash:
                proxy += ",transport=http,path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    proxy += ",host=" + host;
                break;
            default:
                continue;
            }
            if(x.AlterId != 0)
                proxy += ",alterId=" + aid;
            proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
            if(!x.PublicKey.empty())
            {
                proxy += ",public-key=\"" + x.PublicKey + "\"";
                if(!x.ShortID.empty())
                    proxy += ",short-id=" + x.ShortID;
            }
            if(tlssecure || !x.PublicKey.empty())
            {
                std::string vmess_sni = !x.ServerName.empty() ? x.ServerName : (!x.SNI.empty() ? x.SNI : host);
                if(!vmess_sni.empty())
                    proxy += ",sni=" + vmess_sni;
                if(x.PublicKey.empty() && !scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                if(!x.Fingerprint.empty())
                    proxy += ",tls-cert-sha256=" + x.Fingerprint;
            }
            break;
        }
        case ProxyType::VLESS:
        {
            if(!x.VlessEncryption.empty() && x.VlessEncryption != "none")
                continue;
            if(!x.V2rayHttpUpgrade.is_undef() && x.V2rayHttpUpgrade.get())
                continue;

            std::string vless_uuid = !x.UUID.empty() ? x.UUID : id;
            if(vless_uuid.empty())
                continue;

            proxy = "VLESS," + hostname + "," + port + ",\"" + vless_uuid + "\"";
            tfo = tribool();
            switch(hash_(transproto))
            {
            case ""_hash:
            case "tcp"_hash:
            case "raw"_hash:
                if(x.FakeType == "http")
                {
                    proxy += ",transport=http,path=" + (path.empty() ? "/" : path);
                    if(!host.empty())
                        proxy += ",host=" + host;
                }
                else
                    proxy += ",transport=tcp";
                break;
            case "ws"_hash:
                if(!x.PublicKey.empty())
                    continue; // Loon VLESS Reality 仅配合 tcp 使用
                proxy += ",transport=ws,path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    proxy += ",host=" + host;
                break;
            case "http"_hash:
                if(!x.PublicKey.empty())
                    continue;
                proxy += ",transport=http,path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    proxy += ",host=" + host;
                break;
            default:
                continue;
            }

            std::string vless_flow = (x.XTLS == 2) ? "xtls-rprx-vision" : x.Flow;
            if(!vless_flow.empty() && (transproto.empty() || transproto == "tcp" || transproto == "raw"))
            {
                if(vless_flow == "xtls-rprx-vision" || vless_flow == "xtls-rprx-vision-udp443")
                    proxy += ",flow=xtls-rprx-vision";
                else
                    continue;
            }
            if(plugin == "shadow-tls")
            {
                std::string stls_opts = replaceAllDistinct(pluginopts, ";", "&");
                std::string stls_pwd = getUrlArg(stls_opts, "password");
                std::string stls_sni = getUrlArg(stls_opts, "host");
                if(stls_sni.empty())
                    stls_sni = getUrlArg(stls_opts, "sni");
                std::string stls_ver = getUrlArg(stls_opts, "version");
                if(!stls_pwd.empty())
                    proxy += ",shadow-tls-password=\"" + stls_pwd + "\"";
                if(!stls_sni.empty())
                    proxy += ",shadow-tls-sni=" + stls_sni;
                if(!stls_ver.empty())
                    proxy += ",shadow-tls-version=" + stls_ver;
            }

            bool is_reality = !x.PublicKey.empty();
            std::string vless_sni = !x.SNI.empty() ? x.SNI : (!x.ServerName.empty() ? x.ServerName : (!host.empty() ? host : hostname));
            if(is_reality)
            {
                if(vless_sni.empty())
                    continue;
                proxy += ",public-key=\"" + x.PublicKey + "\"";
                if(!x.ShortID.empty())
                    proxy += ",short-id=" + x.ShortID;
                proxy += ",over-tls=true,sni=" + vless_sni;
            }
            else if(tlssecure || !vless_flow.empty())
            {
                proxy += ",over-tls=true";
                if(!vless_sni.empty())
                    proxy += ",sni=" + vless_sni;
                if(!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                if(!x.Fingerprint.empty())
                    proxy += ",tls-cert-sha256=" + x.Fingerprint;
            }
            else
            {
                proxy += ",over-tls=false";
            }
            break;
        }
        case ProxyType::ShadowsocksR:
            proxy = "ShadowsocksR," + hostname + "," + port + "," + method + ",\"" + password + "\",protocol=" + protocol + ",protocol-param=" + protoparam + ",obfs=" + obfs + ",obfs-param=" + obfsparam;
            break;
        case ProxyType::HTTP:
            proxy = "http," + hostname + "," + port;
            if(!username.empty() || !password.empty())
                proxy += "," + username + ",\"" + password + "\"";
            tfo = tribool();
            udp = tribool();
            break;
        case ProxyType::HTTPS:
            proxy = "https," + hostname + "," + port;
            if(!username.empty() || !password.empty())
                proxy += "," + username + ",\"" + password + "\"";
            if(!host.empty())
                proxy += ",sni=" + host;
            else if(!x.SNI.empty())
                proxy += ",sni=" + x.SNI;
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            tfo = tribool();
            udp = tribool();
            break;
        case ProxyType::Trojan:
        {
            proxy = "Trojan," + hostname + "," + port + ",\"" + password + "\"";
            switch(hash_(transproto))
            {
            case ""_hash:
            case "tcp"_hash:
                proxy += ",transport=tcp";
                break;
            case "ws"_hash:
            case "http"_hash:
                proxy += ",transport=ws,path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    proxy += ",host=" + host;
                break;
            default:
                continue;
            }
            if(!x.PublicKey.empty())
            {
                proxy += ",public-key=\"" + x.PublicKey + "\"";
                if(!x.ShortID.empty())
                    proxy += ",short-id=" + x.ShortID;
            }
            if(!x.Alpn.empty())
            {
                std::string alpn_str = join(x.Alpn, ",");
                if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                    proxy += ",alpn=\"" + alpn_str + "\"";
                else
                    proxy += ",alpn=" + alpn_str;
            }
            std::string trojan_sni = !x.SNI.empty() ? x.SNI : (!x.ServerName.empty() ? x.ServerName : host);
            if(!trojan_sni.empty())
                proxy += ",sni=" + trojan_sni;
            if(x.PublicKey.empty() && !scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ",tls-cert-sha256=" + x.Fingerprint;
            break;
        }
        case ProxyType::SOCKS5:
            proxy = "socks5," + hostname + "," + port;
            if (!username.empty() && !password.empty())
                proxy += "," + username + ",\"" + password + "\"";
            proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
            if (tlssecure)
            {
                if(!host.empty())
                    proxy += ",sni=" + host;
                if(!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            }
            tfo = tribool();
            break;
        case ProxyType::WireGuard:
            proxy = "WireGuard, interface-ip=" + x.SelfIP;
            if(!x.SelfIPv6.empty())
                proxy += ", interface-ipv6=" + x.SelfIPv6;
            proxy += ", private-key=\"" + x.PrivateKey + "\"";
            for(const auto &y : x.DnsServers)
            {
                if(isIPv4(y))
                    proxy += ", dns=" + y;
                else if(isIPv6(y))
                    proxy += ", dnsv6=" + y;
            }
            if(x.Mtu > 0)
                proxy += ", mtu=" + std::to_string(x.Mtu);
            if(x.KeepAlive > 0)
                proxy += ", keepalive=" + std::to_string(x.KeepAlive);
            proxy += ", peers=[{" + generatePeer(x, true) + "}]";
            tfo = tribool();
            break;
        case ProxyType::Hysteria2:
        {
            proxy = "Hysteria2," + hostname + "," + port + ",\"" + password + "\"";
            if(!x.SNI.empty())
                proxy += ",sni=" + x.SNI;
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ",tls-cert-sha256=" + x.Fingerprint;
            if(x.OBFS == "salamander" && !x.OBFSParam.empty())
                proxy += ",salamander-password=" + x.OBFSParam;
            std::string hy2_ports = !x.Mport.empty() ? x.Mport : x.Ports;
            if(!hy2_ports.empty() && hy2_ports != port)
            {
                proxy += ",server-ports=\"" + replaceAllDistinct(hy2_ports, "-", ":") + "\"";
                if(x.HopInterval > 0)
                    proxy += ",hop-interval=" + std::to_string(x.HopInterval);
            }
            if(!x.Alpn.empty())
            {
                std::string alpn_str = join(x.Alpn, ",");
                if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                    proxy += ",alpn=\"" + alpn_str + "\"";
                else
                    proxy += ",alpn=" + alpn_str;
            }
            if(x.DownSpeed > 0)
                proxy += ",download-bandwidth=" + std::to_string(x.DownSpeed);
            break;
        }
        case ProxyType::AnyTLS:
            proxy = "AnyTLS," + hostname + "," + port + ",\"" + password + "\"";
            if(!x.SNI.empty())
                proxy += ",sni=" + x.SNI;
            else if(!host.empty())
                proxy += ",sni=" + host;
            if(!x.Alpn.empty())
            {
                std::string alpn_str = join(x.Alpn, ",");
                if(x.Alpn.size() > 1 || alpn_str.find(",") != std::string::npos)
                    proxy += ",alpn=\"" + alpn_str + "\"";
                else
                    proxy += ",alpn=" + alpn_str;
            }
            if(x.PublicKey.empty() && !scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ",tls-cert-sha256=" + x.Fingerprint;
            if(!x.PublicKey.empty())
                proxy += ",public-key=\"" + x.PublicKey + "\"";
            if(!x.ShortID.empty())
                proxy += ",short-id=" + x.ShortID;
            if(x.IdleSessionTimeout > 0)
                proxy += ",idle-session-timeout=" + std::to_string(x.IdleSessionTimeout);
            if(x.MaxOpenStreams > 0)
                proxy += ",max-stream-count=" + std::to_string(x.MaxOpenStreams);
            tfo = tribool();
            break;
        default:
            continue;
        }

        if(!tfo.is_undef())
            proxy += ",fast-open=" + std::string(tfo.get() ? "true" : "false");
        if(!udp.is_undef())
            proxy += ",udp=" + std::string(udp.get() ? "true" : "false");

        if(ext.nodelist)
            output_nodelist += x.Remark + " = " + proxy + "\n";
        else
        {
            ini.set("{NONAME}", x.Remark + " = " + proxy);
            nodelist.emplace_back(x);
            remarks_list.emplace_back(x.Remark);
        }
    }

    if(ext.nodelist)
        return output_nodelist;

    string_multimap original_groups;
    std::string loon_group_section = "Proxy Group";
    if(ini.section_exist("ProxyGroup") && !ini.section_exist("Proxy Group"))
        loon_group_section = "ProxyGroup";
    ini.set_current_section(loon_group_section);
    ini.get_items(original_groups);
    ini.erase_section();

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string group, group_extra;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::Smart:
        case ProxyGroupType::LoadBalance:
        case ProxyGroupType::URLTest:
        case ProxyGroupType::Fallback:
            break;
        case ProxyGroupType::SSID:
            if(x.Proxies.size() < 2)
                continue;
            group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
            group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
            ini.set("{NONAME}", x.Name + " = " + group); //insert order
            continue;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        auto iter = std::find_if(original_groups.begin(), original_groups.end(), [&](const string_multimap::value_type &n)
        {
            return trim(n.first) == x.Name;
        });

        if(iter != original_groups.end())
        {
            string_array vArray = split(iter->second, ",");
            if(vArray.size() > 1)
            {
                if(trim(vArray[vArray.size() - 1]).find("img-url") == 0)
                    filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
            }
        }

        std::string group_type = (x.Type == ProxyGroupType::Smart) ? "url-test" : x.TypeStr();
        group = group_type + ",";
        group += join(filtered_nodelist, ",");
        if(x.Type != ProxyGroupType::Select)
        {
            group += ",url=" + x.Url + ",interval=" + std::to_string(x.Interval);
            if(x.Type == ProxyGroupType::LoadBalance)
            {
                group += ",algorithm=" + std::string(x.Strategy == BalanceStrategy::RoundRobin ? "round-robin" : "pcc");
                if(x.Timeout > 0)
                    group += ",max-timeout=" + std::to_string(x.Timeout);
            }
            if(x.Type == ProxyGroupType::URLTest || x.Type == ProxyGroupType::Smart)
            {
                if(x.Tolerance > 0)
                    group += ",tolerance=" + std::to_string(x.Tolerance);
            }
            if(x.Type == ProxyGroupType::Fallback && x.Timeout > 0)
                group += ",max-timeout=" + std::to_string(x.Timeout);
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -4, ext.overwrite_original_rules, ext.managed_config_prefix);

    return ini.to_string();
}

static std::string formatSingBoxInterval(Integer interval)
{
    std::string result;
    if(interval >= 3600)
    {
        result += std::to_string(interval / 3600) + "h";
        interval %= 3600;
    }
    if(interval >= 60)
    {
        result += std::to_string(interval / 60) + "m";
        interval %= 60;
    }
    if(interval > 0)
        result += std::to_string(interval) + "s";
    return result;
}

static rapidjson::Value buildSingBoxTransport(const Proxy& proxy, rapidjson::MemoryPoolAllocator<>& allocator)
{
    rapidjson::Value transport(rapidjson::kObjectType);
    switch (hash_(proxy.TransferProtocol))
    {
        case "http"_hash:
        {
            if (!proxy.Host.empty())
                transport.AddMember("host", rapidjson::StringRef(proxy.Host.c_str()), allocator);
            [[fallthrough]];
        }
        case "ws"_hash:
        {
            transport.AddMember("type", rapidjson::StringRef(proxy.TransferProtocol.c_str()), allocator);
            if (proxy.Path.empty())
                transport.AddMember("path", "/", allocator);
            else
                transport.AddMember("path", rapidjson::StringRef(proxy.Path.c_str()), allocator);

            rapidjson::Value headers(rapidjson::kObjectType);
            if (!proxy.Host.empty())
                headers.AddMember("Host", rapidjson::StringRef(proxy.Host.c_str()), allocator);
            if (!proxy.Edge.empty())
                headers.AddMember("Edge", rapidjson::StringRef(proxy.Edge.c_str()), allocator);
            transport.AddMember("headers", headers, allocator);
            break;
        }
        case "grpc"_hash:
        {
            transport.AddMember("type", "grpc", allocator);
            std::string grpc_srv = !proxy.GRPCServiceName.empty() ? urlDecode(proxy.GRPCServiceName) : proxy.Path;
            if (!grpc_srv.empty())
                transport.AddMember("service_name", rapidjson::Value(grpc_srv.c_str(), allocator), allocator);
            break;
        }
        default:
            break;
    }
    return transport;
}

static void addSingBoxCommonMembers(rapidjson::Value &proxy, const Proxy &x, const rapidjson::GenericStringRef<rapidjson::Value::Ch> &type, rapidjson::MemoryPoolAllocator<> &allocator)
{
    proxy.AddMember("type", type, allocator);
    proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
    proxy.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()), allocator);
    proxy.AddMember("server_port", x.Port, allocator);
}

static rapidjson::Value stringArrayToJsonArray(const std::string &array, const std::string &delimiter, rapidjson::MemoryPoolAllocator<> &allocator)
{
    rapidjson::Value result(rapidjson::kArrayType);
    string_array vArray = split(array, delimiter);
    for (const auto &x : vArray)
        result.PushBack(rapidjson::Value(trim(x).c_str(), allocator), allocator);
    return result;
}

void proxyToSingBox(std::vector<Proxy> &nodes, rapidjson::Document &json, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    using namespace rapidjson_ext;
    rapidjson::Document::AllocatorType &allocator = json.GetAllocator();
    rapidjson::Value outbounds(rapidjson::kArrayType), route(rapidjson::kArrayType);
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    if (!ext.nodelist)
    {
        auto direct = buildObject(allocator, "type", "direct", "tag", "DIRECT");
        outbounds.PushBack(direct, allocator);
        auto reject = buildObject(allocator, "type", "block", "tag", "REJECT");
        outbounds.PushBack(reject, allocator);
        auto dns = buildObject(allocator, "type", "dns", "tag", "dns-out");
        outbounds.PushBack(dns, allocator);
    }

    for (Proxy &x : nodes)
    {
        std::string type = getProxyTypeName(x.Type);
        if (ext.append_proxy_type)
            x.Remark = "[" + type + "] " + x.Remark;

        processRemark(x.Remark, remarks_list, false);

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        rapidjson::Value proxy(rapidjson::kObjectType);
        switch (x.Type)
        {
            case ProxyType::Shadowsocks:
            {
                addSingBoxCommonMembers(proxy, x, "shadowsocks", allocator);
                proxy.AddMember("method", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if(!x.Plugin.empty() && !x.PluginOption.empty())
                {
                    if (x.Plugin == "simple-obfs")
                        x.Plugin = "obfs-local";
                    proxy.AddMember("plugin", rapidjson::StringRef(x.Plugin.c_str()), allocator);
                    proxy.AddMember("plugin_opts", rapidjson::StringRef(x.PluginOption.c_str()), allocator);
                }
                break;
            }
            case ProxyType::ShadowsocksR:
            {
                addSingBoxCommonMembers(proxy, x, "shadowsocksr", allocator);
                proxy.AddMember("method", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                proxy.AddMember("protocol", rapidjson::StringRef(x.Protocol.c_str()), allocator);
                proxy.AddMember("protocol_param", rapidjson::StringRef(x.ProtocolParam.c_str()), allocator);
                proxy.AddMember("obfs", rapidjson::StringRef(x.OBFS.c_str()), allocator);
                proxy.AddMember("obfs_param", rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
                break;
            }
            case ProxyType::VMess:
            {
                addSingBoxCommonMembers(proxy, x, "vmess", allocator);
                proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()), allocator);
                proxy.AddMember("alter_id", x.AlterId, allocator);
                proxy.AddMember("security", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);

                auto transport = buildSingBoxTransport(x, allocator);
                if (!transport.ObjectEmpty())
                    proxy.AddMember("transport", transport, allocator);
                break;
            }
            case ProxyType::Trojan:
            {
                addSingBoxCommonMembers(proxy, x, "trojan", allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);

                auto transport = buildSingBoxTransport(x, allocator);
                if (!transport.ObjectEmpty())
                    proxy.AddMember("transport", transport, allocator);
                break;
            }
            case ProxyType::WireGuard:
            {
                proxy.AddMember("type", "wireguard", allocator);
                proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
                rapidjson::Value addresses(rapidjson::kArrayType);
                addresses.PushBack(rapidjson::StringRef(x.SelfIP.c_str()), allocator);
                if (!x.SelfIPv6.empty())
                    addresses.PushBack(rapidjson::StringRef(x.SelfIPv6.c_str()), allocator);
                proxy.AddMember("local_address", addresses, allocator);
                proxy.AddMember("private_key", rapidjson::StringRef(x.PrivateKey.c_str()), allocator);

                rapidjson::Value peer(rapidjson::kObjectType);
                peer.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()), allocator);
                peer.AddMember("server_port", x.Port, allocator);
                peer.AddMember("public_key", rapidjson::StringRef(x.PublicKey.c_str()), allocator);
                if (!x.PreSharedKey.empty())
                    peer.AddMember("pre_shared_key", rapidjson::StringRef(x.PreSharedKey.c_str()), allocator);

                if (!x.AllowedIPs.empty())
                {
                    auto allowed_ips = stringArrayToJsonArray(x.AllowedIPs, ",", allocator);
                    peer.AddMember("allowed_ips", allowed_ips, allocator);
                }

                if (!x.ClientId.empty())
                {
                    auto reserved = stringArrayToJsonArray(x.ClientId, ",", allocator);
                    peer.AddMember("reserved", reserved, allocator);
                }

                rapidjson::Value peers(rapidjson::kArrayType);
                peers.PushBack(peer, allocator);
                proxy.AddMember("peers", peers, allocator);
                proxy.AddMember("mtu", x.Mtu, allocator);
                break;
            }
            case ProxyType::Hysteria:
            {
                addSingBoxCommonMembers(proxy, x, "hysteria", allocator);
                if (x.UpSpeed)
                    proxy.AddMember("up_mbps", x.UpSpeed, allocator);
                if (x.DownSpeed)
                    proxy.AddMember("down_mbps", x.DownSpeed, allocator);
                if (!x.OBFS.empty())
                {
                    proxy.AddMember("obfs", rapidjson::StringRef(x.OBFS.c_str()), allocator);
                }

                if (!x.AuthStr.empty())
                {
                    proxy.AddMember("auth_str", rapidjson::StringRef(x.AuthStr.c_str()), allocator);
                    rapidjson::Value auth_str;
                    auth_str.SetString(base64Encode(x.AuthStr).c_str(), allocator);
                    proxy.AddMember("auth", auth_str, allocator);
                }
                if (x.RecvWindowConn)
                    proxy.AddMember("recv_window_conn", x.RecvWindowConn, allocator);
                if (x.RecvWindow)
                    proxy.AddMember("recv_window", x.RecvWindow, allocator);
                if (!x.DisableMtuDiscovery.is_undef())
                    proxy.AddMember("disable_mtu_discovery", x.DisableMtuDiscovery.get(), allocator);

                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if (!x.SNI.empty())
                    tls.AddMember("server_name", rapidjson::StringRef(x.SNI.c_str()), allocator);
                if (!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                if (!x.Alpn.empty())
                {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    for (const auto& item : x.Alpn)
                        alpn.PushBack(rapidjson::StringRef(item.c_str()), allocator);
                    tls.AddMember("alpn", alpn, allocator);
                }
                if (!x.Ca.empty())
                {
                    rapidjson::Value ca_str;
                    ca_str.SetString(x.Ca.c_str(), allocator);
                    tls.AddMember("certificate", ca_str, allocator);
                }
                if (!x.CaStr.empty())
                    tls.AddMember("certificate", rapidjson::StringRef(x.CaStr.c_str()), allocator);
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            case ProxyType::Hysteria2:
            {
                addSingBoxCommonMembers(proxy, x, "hysteria2", allocator);
                std::string hy2_ports = !x.Mport.empty() ? x.Mport : x.Ports;
                if (!hy2_ports.empty() && hy2_ports != std::to_string(x.Port))
                    proxy.AddMember("server_ports", stringArrayToJsonArray(replaceAllDistinct(hy2_ports, "-", ":"), ",", allocator), allocator);
                if (x.UpSpeed)
                    proxy.AddMember("up_mbps", x.UpSpeed, allocator);
                if (x.DownSpeed)
                    proxy.AddMember("down_mbps", x.DownSpeed, allocator);
                if (!x.OBFS.empty())
                {
                    rapidjson::Value obfs(rapidjson::kObjectType);
                    obfs.AddMember("type", rapidjson::StringRef(x.OBFS.c_str()), allocator);
                    if (!x.OBFSParam.empty())
                        obfs.AddMember("password", rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
                    proxy.AddMember("obfs", obfs, allocator);
                }
                if (!x.Password.empty())
                    proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if (x.HopInterval)
                    proxy.AddMember("hop_interval", rapidjson::Value(formatSingBoxInterval(x.HopInterval).c_str(), allocator), allocator);
                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if (!x.SNI.empty())
                    tls.AddMember("server_name", rapidjson::StringRef(x.SNI.c_str()), allocator);
                if (!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                if (!x.Alpn.empty())
                {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    for (const auto& item : x.Alpn)
                        alpn.PushBack(rapidjson::StringRef(item.c_str()), allocator);
                    tls.AddMember("alpn", alpn, allocator);
                }
                if (!x.Ca.empty())
                {
                    rapidjson::Value ca_str(rapidjson::kStringType);
                    ca_str.SetString(x.Ca.c_str(), allocator);
                    tls.AddMember("certificate", ca_str, allocator);
                }
                if (!x.CaStr.empty())
                    tls.AddMember("certificate", rapidjson::StringRef(x.CaStr.c_str()), allocator);
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            case ProxyType::TUIC:
            {
                addSingBoxCommonMembers(proxy, x, "tuic", allocator);

                if (!x.UUID.empty())
                    proxy.AddMember("uuid", rapidjson::StringRef(x.UUID.c_str()), allocator);

                if (!x.Password.empty())
                    proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);

                if (!x.HeartbeatInterval.empty())
                    proxy.AddMember("heartbeat", rapidjson::StringRef(x.HeartbeatInterval.c_str()), allocator);

                if (!x.UdpRelayMode.empty())
                    proxy.AddMember("udp_relay_mode", rapidjson::StringRef(x.UdpRelayMode.c_str()), allocator);

                if (!x.CongestionController.empty())
                    proxy.AddMember("congestion_controller", rapidjson::StringRef(x.CongestionController.c_str()), allocator);

                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if (!x.SNI.empty())
                    tls.AddMember("server_name", rapidjson::StringRef(x.SNI.c_str()), allocator);
                if (!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                if (!x.Alpn.empty())
                {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    for (const auto& item : x.Alpn)
                        alpn.PushBack(rapidjson::StringRef(item.c_str()), allocator);
                    tls.AddMember("alpn", alpn, allocator);
                }
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            case ProxyType::AnyTLS:
            {
                addSingBoxCommonMembers(proxy, x, "anytls", allocator);

                if (!x.Password.empty())
                    proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);

                if (x.IdleSessionCheckInterval)
                    proxy.AddMember("idle_session_check_interval", rapidjson::Value(formatSingBoxInterval(x.IdleSessionCheckInterval).c_str(), allocator), allocator);
                if (x.IdleSessionTimeout)
                    proxy.AddMember("idle_session_timeout", rapidjson::Value(formatSingBoxInterval(x.IdleSessionTimeout).c_str(), allocator), allocator);
                if (x.MinIdleSession)
                    proxy.AddMember("min_idle_session", rapidjson::Value(formatSingBoxInterval(x.MinIdleSession).c_str(), allocator), allocator);

                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if (!x.SNI.empty())
                    tls.AddMember("server_name", rapidjson::StringRef(x.SNI.c_str()), allocator);
                if (!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                else if (!x.Fingerprint.empty())
                    tls.AddMember("insecure", true, allocator);
                if (!x.Alpn.empty()) {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    for (const auto& item : x.Alpn)
                        alpn.PushBack(rapidjson::StringRef(item.c_str()), allocator);
                    tls.AddMember("alpn", alpn, allocator);
                }
                proxy.AddMember("tls", tls, allocator);
                break;
            }

            case ProxyType::VLESS:
            {
                addSingBoxCommonMembers(proxy, x, "vless", allocator);
                std::string pkt_enc = !x.PacketEncoding.empty() ? x.PacketEncoding : "xudp";
                proxy.AddMember("packet_encoding", rapidjson::Value(pkt_enc.c_str(), allocator), allocator);

                std::string vless_uuid = !x.UUID.empty() ? x.UUID : x.UserId;
                if (!vless_uuid.empty())
                    proxy.AddMember("uuid", rapidjson::Value(vless_uuid.c_str(), allocator), allocator);

                if (x.XTLS == 2) {
                    proxy.AddMember("flow", rapidjson::StringRef("xtls-rprx-vision"), allocator);
                } else if (!x.Flow.empty()) {
                    proxy.AddMember("flow", rapidjson::StringRef(x.Flow.c_str()), allocator);
                }

                if (x.TLSSecure || !x.PublicKey.empty())
                {
                    rapidjson::Value tls(rapidjson::kObjectType);
                    tls.AddMember("enabled", true, allocator);
                    std::string vless_sni = !x.SNI.empty() ? x.SNI : (!x.ServerName.empty() ? x.ServerName : x.Host);
                    if (!vless_sni.empty())
                        tls.AddMember("server_name", rapidjson::Value(vless_sni.c_str(), allocator), allocator);
                    if (!scv.is_undef())
                        tls.AddMember("insecure", scv.get(), allocator);
                    if (!x.Alpn.empty()) {
                        rapidjson::Value alpn(rapidjson::kArrayType);
                        for (const auto& item : x.Alpn)
                            alpn.PushBack(rapidjson::StringRef(item.c_str()), allocator);
                        tls.AddMember("alpn", alpn, allocator);
                    }

                    if (!x.PublicKey.empty()) {
                        rapidjson::Value reality(rapidjson::kObjectType);
                        reality.AddMember("enabled", true, allocator);
                        reality.AddMember("public_key", rapidjson::StringRef(x.PublicKey.c_str()), allocator);
                        if (!x.ShortID.empty())
                            reality.AddMember("short_id", rapidjson::StringRef(x.ShortID.c_str()), allocator);
                        tls.AddMember("reality", reality, allocator);

                        rapidjson::Value utls(rapidjson::kObjectType);
                        utls.AddMember("enabled", true, allocator);
                        std::string fp = !x.ClientFingerprint.empty() ? x.ClientFingerprint : "chrome";
                        utls.AddMember("fingerprint", rapidjson::Value(fp.c_str(), allocator), allocator);
                        tls.AddMember("utls", utls, allocator);
                    } else if (!x.ClientFingerprint.empty()) {
                        rapidjson::Value utls(rapidjson::kObjectType);
                        utls.AddMember("enabled", true, allocator);
                        utls.AddMember("fingerprint", rapidjson::StringRef(x.ClientFingerprint.c_str()), allocator);
                        tls.AddMember("utls", utls, allocator);
                    }

                    proxy.AddMember("tls", tls, allocator);
                }

                auto transport = buildSingBoxTransport(x, allocator);
                if (!transport.ObjectEmpty())
                    proxy.AddMember("transport", transport, allocator);

                break;
            }

            case ProxyType::HTTP:
            case ProxyType::HTTPS:
            {
                addSingBoxCommonMembers(proxy, x, "http", allocator);
                proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                break;
            }
            case ProxyType::SOCKS5:
            {
                addSingBoxCommonMembers(proxy, x, "socks", allocator);
                proxy.AddMember("version", "5", allocator);
                proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                break;
            }
            default:
                continue;
        }
        if (x.TLSSecure && !proxy.HasMember("tls"))
        {
            rapidjson::Value tls(rapidjson::kObjectType);
            tls.AddMember("enabled", true, allocator);
            if (!x.SNI.empty())
                tls.AddMember("server_name", rapidjson::StringRef(x.SNI.c_str()), allocator);
            else if (!x.ServerName.empty())
                tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()), allocator);
            else if (!x.Host.empty())
                tls.AddMember("server_name", rapidjson::StringRef(x.Host.c_str()), allocator);
            if (!scv.is_undef())
                tls.AddMember("insecure", scv.get(), allocator);
            if (!x.Alpn.empty())
            {
                rapidjson::Value alpn(rapidjson::kArrayType);
                for (const auto& item : x.Alpn)
                    alpn.PushBack(rapidjson::StringRef(item.c_str()), allocator);
                tls.AddMember("alpn", alpn, allocator);
            }
            if (!x.ClientFingerprint.empty())
            {
                rapidjson::Value utls(rapidjson::kObjectType);
                utls.AddMember("enabled", true, allocator);
                utls.AddMember("fingerprint", rapidjson::StringRef(x.ClientFingerprint.c_str()), allocator);
                tls.AddMember("utls", utls, allocator);
            }
            proxy.AddMember("tls", tls, allocator);
        }
        if (!x.UnderlyingProxy.empty())
        {
            proxy.AddMember("detour", rapidjson::StringRef(x.UnderlyingProxy.c_str()), allocator);
        }
        if (!udp.is_undef() && !udp)
        {
            proxy.AddMember("network", "tcp", allocator);
        }
        if (!tfo.is_undef())
        {
            proxy.AddMember("tcp_fast_open", buildBooleanValue(tfo), allocator);
        }
        nodelist.push_back(x);
        remarks_list.emplace_back(x.Remark);
        outbounds.PushBack(proxy, allocator);
    }

    if (ext.nodelist)
    {
        json | AddMemberOrReplace("outbounds", outbounds, allocator);
        return;
    }

    for (const ProxyGroupConfig &x: extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string type;
        switch (x.Type)
        {
            case ProxyGroupType::Select:
            {
                type = "selector";
                break;
            }
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Smart:
            case ProxyGroupType::Fallback:
            case ProxyGroupType::LoadBalance:
            {
                type = "urltest";
                break;
            }
            default:
                continue;
        }
        for (const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        rapidjson::Value group(rapidjson::kObjectType);

        group.AddMember("type", rapidjson::Value(type.c_str(), allocator), allocator);
        group.AddMember("tag", rapidjson::Value(x.Name.c_str(), allocator), allocator);

        rapidjson::Value group_outbounds(rapidjson::kArrayType);
        for (const std::string& y: filtered_nodelist)
        {
            group_outbounds.PushBack(rapidjson::Value(y.c_str(), allocator), allocator);
        }
        group.AddMember("outbounds", group_outbounds, allocator);

        if (x.Type == ProxyGroupType::URLTest || x.Type == ProxyGroupType::Smart)
        {
            group.AddMember("url", rapidjson::Value(x.Url.c_str(), allocator), allocator);
            group.AddMember("interval", rapidjson::Value(formatSingBoxInterval(x.Interval).c_str(), allocator), allocator);
            if (x.Tolerance > 0)
                group.AddMember("tolerance", x.Tolerance, allocator);
        }
        outbounds.PushBack(group, allocator);
    }

    if (global.singBoxAddClashModes)
    {
        auto global_group = rapidjson::Value(rapidjson::kObjectType);
        global_group.AddMember("type", "selector", allocator);
        global_group.AddMember("tag", "GLOBAL", allocator);
        global_group.AddMember("outbounds", rapidjson::Value(rapidjson::kArrayType), allocator);
        global_group["outbounds"].PushBack("DIRECT", allocator);
        for (auto &x: remarks_list)
        {
            global_group["outbounds"].PushBack(rapidjson::Value(x.c_str(), allocator), allocator);
        }
        outbounds.PushBack(global_group, allocator);
    }

    json | AddMemberOrReplace("outbounds", outbounds, allocator);
}

std::string proxyToSingBox(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    using namespace rapidjson_ext;
    rapidjson::Document json;

    if (!ext.nodelist)
    {
        json.Parse(base_conf.data());
        if (json.HasParseError())
        {
            writeLog(0, "sing-box base loader failed with error: " +
                        std::string(rapidjson::GetParseError_En(json.GetParseError())), LOG_LEVEL_ERROR);
            return "";
        }
    }
    else
    {
        json.SetObject();
    }

    proxyToSingBox(nodes, json, ruleset_content_array, extra_proxy_group, ext);

    if(ext.nodelist || !ext.enable_rule_generator)
        return json | SerializeObject();

    rulesetToSingBox(json, ruleset_content_array, ext.overwrite_original_rules);

    return json | SerializeObject();
}

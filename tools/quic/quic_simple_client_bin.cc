// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
//   TODO(rtenneti): make --host optional by getting IP Address of URL's host.
//
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//
// Standard request/response:
//   quic_client http://www.google.com  --host=${IP}
//   quic_client http://www.google.com --quiet  --host=${IP}
//   quic_client https://www.google.com --port=443  --host=${IP}
//
// Use a specific version:
//   quic_client http://www.google.com --quic_version=23  --host=${IP}
//
// Send a POST instead of a GET:
//   quic_client http://www.google.com --body="this is a POST body" --host=${IP}
//
// Append additional headers to the request:
//   quic_client http://www.google.com  --host=${IP}
//               --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//   quic_client mail.google.com --host=${IP}
//
// Try to connect to a host which does not speak QUIC:
//   Get IP address of the www.example.com
//   IP=`dig www.example.com +short | head -1`
//   quic_client http://www.example.com --host=${IP}

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/task/task_scheduler/task_scheduler.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/third_party/quic/core/quic_error_codes.h"
#include "net/third_party/quic/core/quic_packets.h"
#include "net/third_party/quic/core/quic_server_id.h"
#include "net/third_party/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quic/platform/api/quic_text_utils.h"
#include "net/third_party/spdy/core/spdy_header_block.h"
#include "net/tools/quic/quic_simple_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "url/gurl.h"

#include "net/third_party/quic/tools/quic_client_base.h"
#include <string> //Jerry
#include <fstream> //Jerry
#include <algorithm> //Jerry
//#include <thread> //Jerry
//#include "base/threading/simple_thread.h" //Jerry
//#include "buildtools/third_party/libc++/trunk/include/thread"
//#include "/home/jerry/Desktop/cppzmq/zmq.hpp"
//#include "net/third_party/zmq/zmq.hpp"
//#include <zmq.h>
//#include <unistd.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
using net::CertVerifier;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using quic::ProofVerifier;
using net::ProofVerifierChromium;
using quic::QuicStringPiece;
using quic::QuicTextUtils;
using net::TransportSecurityState;
using spdy::SpdyHeaderBlock;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

using quic::QuicClientBase;
using quic::QuicString;





//using namespace quic; //Jerry


//using std::type_info;
using namespace std;
#include <chrono>
#include <thread>
using namespace std::this_thread; // sleep_for, sleep_until
using namespace std::chrono; // nanoseconds, system_clock, seconds
//Jerry

// The IP or hostname the quic client will connect to.
string FLAGS_host = "";
// The port to connect to.
int32_t FLAGS_port = 0;
// If set, send a POST with this body.
string FLAGS_body = "";
// If set, contents are converted from hex to ascii, before sending as body of
// a POST. e.g. --body_hex=\"68656c6c6f\"
string FLAGS_body_hex = "";
// A semicolon separated list of key:value pairs to add to request headers.
string FLAGS_headers = "";
// Set to true for a quieter output experience.
bool FLAGS_quiet = false;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
bool FLAGS_version_mismatch_ok = false;
// If true, an HTTP response code of 3xx is considered to be a successful
// response, otherwise a failure.
bool FLAGS_redirect_is_success = true;
// Initial MTU of the connection.
int32_t FLAGS_initial_mtu = 0;

class FakeProofVerifier : public quic::ProofVerifier {
 public:
  quic::QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      quic::QuicTransportVersion quic_version,
      quic::QuicStringPiece chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const quic::ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* details,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override {
    return quic::QUIC_SUCCESS;
  }

  quic::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const std::vector<std::string>& certs,
      const quic::ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override {
    return quic::QUIC_SUCCESS;
  }

  std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override {
    return nullptr;
  }
};


/*
void just_test(net::QuicSimpleClient* client){

std::vector<QuicString> url_list;

url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track51_9.m4s");
url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track52_9.m4s");
client->SendRequestsAndWaitForResponse(url_list);

//while(client->WaitForEvents()){}
//cout<<"in here: "<<mm<<endl;

}
*/

int main(int argc, char* argv[]) {

  
  std::cout<<"please!!!!!!!!---------------------"<<std::endl; //Jerry

  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  const base::CommandLine::StringVector& urls = line->GetArgs();
  base::TaskScheduler::CreateAndStartWithDefaultParams("quic_client");

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  if (line->HasSwitch("h") || line->HasSwitch("help") || urls.empty()) {
    const char* help_str =
        "Usage: quic_client [options] <url>\n"
        "\n"
        "<url> with scheme must be provided (e.g. http://www.google.com)\n\n"
        "Options:\n"
        "-h, --help                  show this help message and exit\n"
        "--host=<host>               specify the IP address of the hostname to "
        "connect to\n"
        "--port=<port>               specify the port to connect to\n"
        "--body=<body>               specify the body to post\n"
        "--body_hex=<body_hex>       specify the body_hex to be printed out\n"
        "--headers=<headers>         specify a semicolon separated list of "
        "key:value pairs to add to request headers\n"
        "--quiet                     specify for a quieter output experience\n"
        "--quic-version=<quic version> specify QUIC version to speak\n"
        "--version_mismatch_ok       if specified a version mismatch in the "
        "handshake is not considered a failure\n"
        "--redirect_is_success       if specified an HTTP response code of 3xx "
        "is considered to be a successful response, otherwise a failure\n"
        "--initial_mtu=<initial_mtu> specify the initial MTU of the connection"
        "\n"
        "--disable-certificate-verification do not verify certificates\n";
    cout << help_str;
    exit(0);
  }
  if (line->HasSwitch("host")) {
    FLAGS_host = line->GetSwitchValueASCII("host");
  }
  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      std::cerr << "--port must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("body")) {
    FLAGS_body = line->GetSwitchValueASCII("body");
  }
  if (line->HasSwitch("body_hex")) {
    FLAGS_body_hex = line->GetSwitchValueASCII("body_hex");
  }
  if (line->HasSwitch("headers")) {
    FLAGS_headers = line->GetSwitchValueASCII("headers");
  }
  if (line->HasSwitch("quiet")) {
    FLAGS_quiet = true;
  }
  if (line->HasSwitch("quic-version")) {
    int quic_version;
    if (base::StringToInt(line->GetSwitchValueASCII("quic-version"),
                          &quic_version)) {
      FLAGS_quic_version = quic_version;
    }
  }
  if (line->HasSwitch("version_mismatch_ok")) {
    FLAGS_version_mismatch_ok = true;
  }
  if (line->HasSwitch("redirect_is_success")) {
    FLAGS_redirect_is_success = true;
  }
  if (line->HasSwitch("initial_mtu")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("initial_mtu"),
                           &FLAGS_initial_mtu)) {
      std::cerr << "--initial_mtu must be an integer\n";
      return 1;
    }
  }

  VLOG(1) << "server host: " << FLAGS_host << " port: " << FLAGS_port
          << " body: " << FLAGS_body << " headers: " << FLAGS_headers
          << " quiet: " << FLAGS_quiet
          << " quic-version: " << FLAGS_quic_version
          << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
          << " redirect_is_success: " << FLAGS_redirect_is_success
          << " initial_mtu: " << FLAGS_initial_mtu;

  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  // Determine IP address to connect to from supplied hostname.
  quic::QuicIpAddress ip_addr;
  
//  std::cout<<"urls: "<<urls[0]<<std::endl; //Jerry

  GURL url(urls[0]);

//  std::cout<<"url: "<<url<<std::endl; //Jerry

  string host = FLAGS_host;
  if (host.empty()) {
    host = url.host();
  }
  int port = FLAGS_port;
  if (port == 0) {
    port = url.EffectiveIntPort();
  }
  if (!ip_addr.FromString(host)) {
    net::AddressList addresses;
    int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
    if (rv != net::OK) {
      LOG(ERROR) << "Unable to resolve '" << host
                 << "' : " << net::ErrorToShortString(rv);
      return 1;
    }
    ip_addr =
        quic::QuicIpAddress(quic::QuicIpAddressImpl(addresses[0].address()));
  }

  string host_port = quic::QuicStrCat(ip_addr.ToString(), ":", port);
  VLOG(1) << "Resolved " << host << " to " << host_port << endl;

  // Build the client, and try to connect.
  quic::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                               net::PRIVACY_MODE_DISABLED);
  quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(quic::ParsedQuicVersion(
        quic::PROTOCOL_QUIC_CRYPTO,
        static_cast<quic::QuicTransportVersion>(FLAGS_quic_version)));
  }
  // For secure QUIC we need to verify the cert chain.
  std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  std::unique_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  std::unique_ptr<MultiLogCTVerifier> ct_verifier(new MultiLogCTVerifier());
  std::unique_ptr<net::CTPolicyEnforcer> ct_policy_enforcer(
      new net::DefaultCTPolicyEnforcer());
  std::unique_ptr<quic::ProofVerifier> proof_verifier;
  if (line->HasSwitch("disable-certificate-verification")) {
    proof_verifier.reset(new FakeProofVerifier());
  } else {
    proof_verifier.reset(new ProofVerifierChromium(
        cert_verifier.get(), ct_policy_enforcer.get(),
        transport_security_state.get(), ct_verifier.get()));
  }
  net::QuicSimpleClient client(quic::QuicSocketAddress(ip_addr, port),
                               server_id, versions, std::move(proof_verifier));
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : quic::kDefaultMaxPacketSize);
  if (!client.Initialize()) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client.Connect()) {
    quic::QuicErrorCode error = client.session()->error();
    if (FLAGS_version_mismatch_ok && error == quic::QUIC_INVALID_VERSION) {
      cout << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << ParsedQuicVersionVectorToString(versions)
           << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    cerr << "Failed to connect to " << host_port
         << ". Error: " << quic::QuicErrorCodeToString(error) << endl;
    return 1;
  }
  cout << "Connected to " << host_port << endl;

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = quic::QuicTextUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.host();
  header_block[":path"] = url.path();
//  std::cout<< "url_path" << url.path()<<std::endl;
//  header_block[":path"] = "/api/download/packagelist.txt";




  // Append any additional headers supplied on the command line.
  for (quic::QuicStringPiece sp :
       quic::QuicTextUtils::Split(FLAGS_headers, ';')) {
    quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<quic::QuicStringPiece> kv = quic::QuicTextUtils::Split(sp, ':');
    quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }




  std::vector<QuicString> url_list;  

/*
  url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track51_9.m4s");
  url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track52_9.m4s");
  url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track53_9.m4s");
  url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track54_9.m4s");
  url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track55_9.m4s");
  url_list.push_back("https://www.example.org/coaster_10x10_qp32_tile_dash_track56_9.m4s");
*/

  std::vector<QuicString> url_patch_list;
//  mp4_list.push_back("https://www.example.org/aa.txt");  
//  mp4_list.push_back("https://www.example.org/aa.txt");
//  mp4_list.push_back("https://www.example.org/aa.txt");


  // Make sure to store the response, for later output.
  client.set_store_response(true);

  // Send the request.
//  client.SendRequestAndWaitForResponse(header_block, body, /*fin=*/true); //Oringinal!!!

//Jerry
//  client.SendRequest(header_block, body, /*fin=*/true);
//  client.SendRequestsAndWaitForResponse(url_list);

//  sleep_for(2s);
//  client.SendRequestsAndWaitForResponse(mp4_list); 



    int current_number=1;
    int last_number=1;
    string file_name;
    
    int current_patch_number=1;
    int last_patch_number=1;

    while(1){
    client.WaitForEvents(); // important!!! check if there is new response every loop
    // for regular
    std::ifstream inFile("/home/jerry/Desktop/for_quic/quic.txt");    
    current_number=std::count(std::istreambuf_iterator<char>(inFile), 
             std::istreambuf_iterator<char>(), '\n');
    inFile.close();
    
    
    // for patch
    std::ifstream inFile_patch("/home/jerry/Desktop/for_quic/quic_patch.txt");
    current_patch_number=std::count(std::istreambuf_iterator<char>(inFile_patch),
    std::istreambuf_iterator<char>(), '\n');
    inFile_patch.close();
    
/*
    // for regular
    if (current_number != last_number && current_number!=0){
      cout<<"regular"<<endl;
      url_list.clear();
      std::ifstream inFile("/home/jerry/Desktop/for_quic/quic.txt");

    for (int lineno = 0; lineno < current_number; lineno++){
      getline (inFile,file_name);
      if ((lineno >= last_number)||(lineno>= last_number-1 && last_number==1 )){
//          cout << file_name<< endl;
         url_list.push_back(file_name);
      }
    }

     client.SendRequestsAndWaitForResponse(url_list,7); //request_file
     last_number = current_number;
     inFile.close();
    }
    
  */   
    // for patch
    if (current_patch_number != last_patch_number && current_patch_number!=0){
      cout<<"patch"<<endl; 
      url_patch_list.clear();
      std::ifstream inFile_patch("/home/jerry/Desktop/for_quic/quic_patch.txt");

    for (int lineno = 0; lineno < current_patch_number; lineno++){
      getline (inFile_patch,file_name);
      if ((lineno >= last_patch_number)||(lineno>= last_patch_number-1 && last_patch_number==1 )){
//          cout << file_name<< endl;
         url_patch_list.push_back(file_name);
      }
    }

     client.SendRequestsAndWaitForResponse(url_patch_list,1); //request_file
     last_patch_number = current_patch_number;
     inFile_patch.close();
    }


    // for regular
    if (current_number != last_number && current_number!=0){
      cout<<"regular"<<endl;
      url_list.clear();
      std::ifstream inFile("/home/jerry/Desktop/for_quic/quic.txt");

    for (int lineno = 0; lineno < current_number; lineno++){
      getline (inFile,file_name);
      if ((lineno >= last_number)||(lineno>= last_number-1 && last_number==1 )){
//          cout << file_name<< endl;
         url_list.push_back(file_name);
      }
    }

     client.SendRequestsAndWaitForResponse(url_list,7); //request_file
     last_number = current_number;
     inFile.close();
    }

    
    
    }




//   while(client.WaitForEvents()){ } //Jerry

// Jerry


  // Print request and response details.

  if (!FLAGS_quiet) {
    cout << "Request:" << endl;
    cout << "headers:" << header_block.DebugString();
    if (!FLAGS_body_hex.empty()) {
      // Print the user provided hex, rather than binary body.
      cout << "body:\n"
           << quic::QuicTextUtils::HexDump(
                  quic::QuicTextUtils::HexDecode(FLAGS_body_hex))
           << endl;
    } else {
      cout << "body: " << body << endl;
    }
    cout << endl;
    cout << "Response:" << endl;
    cout << "headers: " << client.latest_response_headers() << endl;
    string response_body = client.latest_response_body();
    if (!FLAGS_body_hex.empty()) {
      // Assume response is binary data.
    } else {
      cout << "body: " << response_body << endl;
    }
    cout << "trailers: " << client.latest_response_trailers() << endl;
  }

  size_t response_code = client.latest_response_code();
  if (response_code >= 200 && response_code < 300) {
    cout << "Request succeeded (" << response_code << ")." << endl;
    return 0;
  } else if (response_code >= 300 && response_code < 400) {
    if (FLAGS_redirect_is_success) {
      cout << "Request succeeded (redirect " << response_code << ")." << endl;
      return 0;
    } else {
      cout << "Request failed (redirect " << response_code << ")." << endl;
      return 1;
    }
  } else {
    cerr << "Request failed (" << response_code << ")." << endl;
    return 1;
  }
}

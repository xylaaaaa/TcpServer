#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <sys/stat.h>
#include "../server.hpp"

#define DEFALT_TIMEOUT 10

std::unordered_map<int, std::string> _statu_msg = {
    {100,  "Continue"},
    {101,  "Switching Protocol"},
    {102,  "Processing"},
    {103,  "Early Hints"},
    {200,  "OK"},
    {201,  "Created"},
    {202,  "Accepted"},
    {203,  "Non-Authoritative Information"},
    {204,  "No Content"},
    {205,  "Reset Content"},
    {206,  "Partial Content"},
    {207,  "Multi-Status"},
    {208,  "Already Reported"},
    {226,  "IM Used"},
    {300,  "Multiple Choice"},
    {301,  "Moved Permanently"},
    {302,  "Found"},
    {303,  "See Other"},
    {304,  "Not Modified"},
    {305,  "Use Proxy"},
    {306,  "unused"},
    {307,  "Temporary Redirect"},
    {308,  "Permanent Redirect"},
    {400,  "Bad Request"},
    {401,  "Unauthorized"},
    {402,  "Payment Required"},
    {403,  "Forbidden"},
    {404,  "Not Found"},
    {405,  "Method Not Allowed"},
    {406,  "Not Acceptable"},
    {407,  "Proxy Authentication Required"},
    {408,  "Request Timeout"},
    {409,  "Conflict"},
    {410,  "Gone"},
    {411,  "Length Required"},
    {412,  "Precondition Failed"},
    {413,  "Payload Too Large"},
    {414,  "URI Too Long"},
    {415,  "Unsupported Media Type"},
    {416,  "Range Not Satisfiable"},
    {417,  "Expectation Failed"},
    {418,  "I'm a teapot"},
    {421,  "Misdirected Request"},
    {422,  "Unprocessable Entity"},
    {423,  "Locked"},
    {424,  "Failed Dependency"},
    {425,  "Too Early"},
    {426,  "Upgrade Required"},
    {428,  "Precondition Required"},
    {429,  "Too Many Requests"},
    {431,  "Request Header Fields Too Large"},
    {451,  "Unavailable For Legal Reasons"},
    {501,  "Not Implemented"},
    {502,  "Bad Gateway"},
    {503,  "Service Unavailable"},
    {504,  "Gateway Timeout"},
    {505,  "HTTP Version Not Supported"},
    {506,  "Variant Also Negotiates"},
    {507,  "Insufficient Storage"},
    {508,  "Loop Detected"},
    {510,  "Not Extended"},
    {511,  "Network Authentication Required"}
};

std::unordered_map<std::string, std::string> _mime_msg = {
    {".aac",        "audio/aac"},
    {".abw",        "application/x-abiword"},
    {".arc",        "application/x-freearc"},
    {".avi",        "video/x-msvideo"},
    {".azw",        "application/vnd.amazon.ebook"},
    {".bin",        "application/octet-stream"},
    {".bmp",        "image/bmp"},
    {".bz",         "application/x-bzip"},
    {".bz2",        "application/x-bzip2"},
    {".csh",        "application/x-csh"},
    {".css",        "text/css"},
    {".csv",        "text/csv"},
    {".doc",        "application/msword"},
    {".docx",       "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".eot",        "application/vnd.ms-fontobject"},
    {".epub",       "application/epub+zip"},
    {".gif",        "image/gif"},
    {".htm",        "text/html"},
    {".html",       "text/html"},
    {".ico",        "image/vnd.microsoft.icon"},
    {".ics",        "text/calendar"},
    {".jar",        "application/java-archive"},
    {".jpeg",       "image/jpeg"},
    {".jpg",        "image/jpeg"},
    {".js",         "text/javascript"},
    {".json",       "application/json"},
    {".jsonld",     "application/ld+json"},
    {".mid",        "audio/midi"},
    {".midi",       "audio/x-midi"},
    {".mjs",        "text/javascript"},
    {".mp3",        "audio/mpeg"},
    {".mpeg",       "video/mpeg"},
    {".mpkg",       "application/vnd.apple.installer+xml"},
    {".odp",        "application/vnd.oasis.opendocument.presentation"},
    {".ods",        "application/vnd.oasis.opendocument.spreadsheet"},
    {".odt",        "application/vnd.oasis.opendocument.text"},
    {".oga",        "audio/ogg"},
    {".ogv",        "video/ogg"},
    {".ogx",        "application/ogg"},
    {".otf",        "font/otf"},
    {".png",        "image/png"},
    {".pdf",        "application/pdf"},
    {".ppt",        "application/vnd.ms-powerpoint"},
    {".pptx",       "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".rar",        "application/x-rar-compressed"},
    {".rtf",        "application/rtf"},
    {".sh",         "application/x-sh"},
    {".svg",        "image/svg+xml"},
    {".swf",        "application/x-shockwave-flash"},
    {".tar",        "application/x-tar"},
    {".tif",        "image/tiff"},
    {".tiff",       "image/tiff"},
    {".ttf",        "font/ttf"},
    {".txt",        "text/plain"},
    {".vsd",        "application/vnd.visio"},
    {".wav",        "audio/wav"},
    {".weba",       "audio/webm"},
    {".webm",       "video/webm"},
    {".webp",       "image/webp"},
    {".woff",       "font/woff"},
    {".woff2",      "font/woff2"},
    {".xhtml",      "application/xhtml+xml"},
    {".xls",        "application/vnd.ms-excel"},
    {".xlsx",       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".xml",        "application/xml"},
    {".xul",        "application/vnd.mozilla.xul+xml"},
    {".zip",        "application/zip"},
    {".3gp",        "video/3gpp"},
    {".3g2",        "video/3gpp2"},
    {".7z",         "application/x-7z-compressed"}
};

class Util {
    public:
        static size_t Split(const std::string &src, const std::stirng &sep, std::vector<std::string> *array) {
            size_t offset = 0;
            // 有10个字符，offset是查找的起始位置，范围应该是0~9，offset==10就代表已经越界了
            while(offset < src.size()) {
                size_t pos = src.find(sep, offset);//在src字符串偏移量offset处，开始向后查找sep字符/字串，返回查找到的位置
                if (pos == std::string::npos) {//没有找到特定的字符
                    //将剩余的部分当作一个字串，放入arry中
                    if(pos == src.size()) break;
                    arry->push_back(src.substr(offset));
                    return arry->size();
                }
                if (pos == offset) {
                    offset = pos + sep.size();
                    continue;//当前字串是一个空的，没有内容
                }
                arry->push_back(src.substr(offset, pos - offset));
                offset = pos + sep.size();
            }
            return arry->size();
        }
        static bool ReadFile(const std::string &filename, std::string *buf) {
            std::ifstream ifs(filename, std::ios::binary);
            if (ifd.is_open() == false) {
                printf("OPEN %s FILE FAILED!!", filename.c_str());
                return false;
            }
            size_t fsize = 0;
            ifs.seekg(0, ifs.end);
            fsize = ifs.tellg();
            ifs.seekg(0, ifs.beg);
            buf->resize(fsize);
            ifs.read(&(*buf)[0], fsize);
            if (ifs.good() == false) {
                printf("READ %s FILE FAILD", filename.c_str());
                ifs.close();
                return false;
            }
            ifs.close();
            return true;
        }

        static bool WriteFile(const string &filename, const std::string &buf) {
            std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
            if (ofs.is_open() == false) {
                printf("OPEN %s FILE FAILED!!", filename.c_str());
                return false;
            }
            ofs.write(buf.c_str(), buf.size());
            if (ofs.good() == false) {
                ERR_LOG("WRITE %s FILE FAILED!", filename.c_str());
                ofs.close();    
                return false;
            }
            ofs.close();
            return true;
        }
        //URL编码，避免URL中资源路径与查询字符串中的特殊字符与HTTP请求中特殊字符产生歧义
        //编码格式：将特殊字符的ascii值，转换为两个16进制字符，前缀%   C++ -> C%2B%2B
        //  不编码的特殊字符： RFC3986文档规定 . - _ ~ 字母，数字属于绝对不编码字符
        //RFC3986文档规定，编码格式 %HH 
        //W3C标准中规定，查询字符串中的空格，需要编码为+， 解码则是+转空格
        static std::string UrlEncode(const std::string url, bool convert_space_to_plus) {
            std::string res;
            for (auto &c : url) {
                if (c == '.' || c == '-' || c == '_' || c == '~' || isalnum(c)) {
                    res += c;
                    continue;
                }
                if (c == ' ' && convert_space_to_plus == true) {
                    res += '+';
                    continue;
                }
                char tmp[4] = {0};
                snprintf(tmp, 4, "%%%02X", c);
                res += tmp;
            }
            return res;
        }

        static char HEXTOI(char c) {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }else if (c >= 'a' && c <= 'z') {
                return c - 'a' + 10;
            }else if (c >= 'A' && c <= 'Z') {
                return c - 'A' + 10;
            }
            return -1; 
        }

        static std::string UrlDecode(const std::string url, bool convert_space_to_plus) {
            std::stirng res;
            for (int i = 0; i < url.size(); i++) {
                if (url[i] == '+' && convert_space_to_plus == true) {
                    res += ' ';
                    continue;
                }
                if (url[i] == '%' && (i + 2) < url.size()) {
                    char v1 = HEXTOI(url[i + 1]);
                    char v2 = HEXTOI(url[i + 2]);
                    char v = v1 * 16 + v2;
                    res += v;
                    i += 2;
                    continue;
                }
                res += url[i];
            }
            return res;
        }

        static std::string StatuDesc(int statu) {
            auto it = _statu_msg.find(statu);
            if (it != _statu_msg.end()) {
                return it->second;
            }
            return "Unknow";
        }

        static std::string ExtMime(const std::string &filename) {
            size_t pos = filename.find_last_of('.');
            if (pos == std::string::npos) {
                return "application/octet-stream";
            }
            std::string ext = filename.substr(pos);
            auto it = _mime_msg.find(ext);
            if (it == _mime_msg.end()) {
                return "application/octet-stream";
            }
            return it->second;
        }

        static bool IsDirectory(const std::string &filename) {
            struct stat st;
            int ret = stat(filename.c_str(), &st);
            if (ret < 0) { return false; }
            return S_ISDIR(st.st_mode);
        }

        static bool IsRegular(const std::string &filename) {
            struct stat st;
            stat(filename.c_str(), &st);
            if (ret < 0) { return false; }
            return S_ISREG(st.st_mode);
        }

        //http请求的资源路径有效性判断
        // /index.html  --- 前边的/叫做相对根目录  映射的是某个服务器上的子目录
        // 想表达的意思就是，客户端只能请求相对根目录中的资源，其他地方的资源都不予理会
        // /../login, 这个路径中的..会让路径的查找跑到相对根目录之外，这是不合理的，不安全的
        static bool VaildPath(const std::string &path) {
            std::vector<std::string> subdir;
            Split(path, "/", &subdir);
            int level = 0;
            for (auto &dir : subdir) {
                if (dir == "..") {
                    level--;
                    if (level < 0) return false;
                    continue;
                }
                level++;
            }
            return true;
        }
};

class HttpRequest {
    public:
        std::string _method; // 请求方法
        std::string _path;   // 资源路径
        std::string _version; // 协议版本
        std::string _body;  // 请求正文
        std::string _matches; // 资源路径的正则提取数据
        std::unordered_map<std::string, std::string> _headers; // 头部字段
        std::unordered_map<std::string, std::string> _params;
    public:
        HttpRequest():_version("HTTP/1.1") {}
        void ReSet() {
            _method.clear();
            _path.clear();
            _version = "HTTP/1.1";
            _body.clear();
            std::smatch match;
            _matches.swap(match);
            _headers.clear();
            _params.clear();
        }
        // 插入头部字段
        void SetHeader(const std::string &key, const std::string &val) {
            _headers.insert(std::make_pair(key, val));
        }
        // 判断是否存在指定头部字段
        bool HasHeader(const std::string &key) const {
            auto it = _headers.find(key);
            if (it == _headers.end()) {
                return false;
            }
            return true;
        }
        // 获取指定头部字段的值
        std::string GetHeader(const std::string &key) const {
            auto it = _headers.find(key);
            if (it == _headers.end()) {
                return "";
            }
            return it->second;
        }
        // 插入查询字符串
        void SetParam(const std::string &key, const std::string &val) {
            _params.insert(std::make_pair(key, val));
        }
        //判断是否有某个指定的查询字符串
        bool HasParam(const std::string &key) const {
            auto it = _params.find(key);
            if (it == _params.end()) {
                return false;
            }
            return true;
        }
         //获取指定的查询字符串
         std::string GetParam(const std::string &key) const {
            auto it = _params.find(key);
            if (it == _params.end()) {
                return "";
            }
            return it->second;
        }
        //获取正文长度
        size_t ContentLength() const {
            bool ret = HasHeader("Content-Length");
            if (ret == false) {
                return 0;
            }
            std::string clen = GetHeader("Content-Length");
            return std::stol(clen);
        }
        // 判断是否为短链接
        bool Close() const {
            if (HasHeader("Connection") == true && GetHeader("Connection") == "keep-alive") {
                return false;
            }
            return true;
        }
};

class HttpResponse {
    public:
        int _statu;
        bool _redirect_flag;
        std::string _body;
        std::string _redirect_url;
        std::unordered_map<std::string, std::string> _headers;
    public:
        HttpResponse():_redirect_url(false), _statu(200) {}
        HttpResponse(int statu) : _redirect_url(false), _statu(statu) {}
        void ReSet() {
            _statu = 200;
            _redirect_flag = false;
            _body.clear();
            _redirect_url.clear();
            _headers.clear();
        }
        void SetHeader(const std::string &key, const std::string &val) {
            _headers.insert(std::make_pair(key, val));
        }
        bool HasHeader(const std::stirng &key) {
            auto it = _headers.find(key);
            if (it == _headers.end()) {
                return false;
            }
            return true;
        }
        std::string GetHeader(const std::string &key) {
            auto it = _headers.find(key);
            if (it == _headers.end()) {
                return "";
            }
            return it->second;
        }
        void SetContent(const std::string &body, const std::string &type = "text/html") {
            _body = body;
            SetHeader("Content-Type", type);
        }
        void SetRedirect(const std::string &url, int statu = 302) {
            _statu = statu;
            _redirect_flag = true;
            _redirect_url = url;
        }
        bool Close() {
            // 没有Connection字段，或者有Connection但是值是close，则都是短链接，否则就是长连接
            if (HasHeader("Connection") == true && GetHeader("Connection") == "keep-alive") {
                return false;
            }
            return true;
        }
};

typedef enum {
    RECV_HTTP_ERROR,
    RECV_HTTP_LINE,
    RECV_HTTP_HEAD,
    RECV_HTTP_BODY,
    RECV_HTTP_OVER
}HttpRecvStatu;

#define MAX_LINE 8192
class HttpContext {
    private:
        int _resp_statu;
        HttpRecvStatu _recv_statu;
        HttpRequest _request; // 已经解析得到的请求信息
    private:
        bool ParseHttpLine(const std::string &line) {
            std::smatch matchs;
            std::regex e("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?", std::regex::icase);
            bool ret = std::regex_match(line, matches, e);
            if (ret == false) {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_statu = 400; // BAD REQUEST
                return false;
            }
            //0 : GET /bitejiuyeke/login?user=xiaoming&pass=123123 HTTP/1.1
            //1 : GET
            //2 : /bitejiuyeke/login
            //3 : user=xiaoming&pass=123123
            //4 : HTTP/1.1
            //请求方法的获取
            _request._method = matches[1];
            std::transform(_request._method.begin(), _request._method.end(), _request._method._method.begin(), ::toupper); // 原地将全部字母变成大写
            // 资源路径的获取，需要进行URL编码操作，但是不需要空格转+
            _request.path = Util::UrlDecode(matches[2], false);
            //协议版本获取
            _request._version = matches[4];
            // 查询字符串的获取与处理
            std::vector<std::string> query_string_arry;
            std::string query_string = matches[3];
            Util::Split(query_string, "&", &query_string_arry);
            for (auto &str : query_string_arry) {
                size_t pos = str.find("=");
                if (pos == std::string::npos) {
                    _recv_statu = RECV_HTTP_ERROR;
                    _resp_statu = 400; // BAD REQUEST;
                }
                std::string key = UtilDecode(str.substr(0, pos), true);
                std::string val = Util::UrlDecode(str.substr(pos + 1), true);
                _request.SetParam(key, val);
            }
            return true;
        }
        bool RecvHttpLine(Buffer *buf) {
            if (_recv_statu != RECV_HTTP_LINE) return false;
            // 1.获取一行数据，带有末尾的换行
            std::string line = buf->GetLineAndPop();
            // 2.需要考虑的一些要素：缓冲区中的数据不足一行，获取的一行数据超大
            if (line.size() == 0) {
                //缓冲区中的数据不足一行，则需判断缓冲区的可读数据长度，如果长了都不足一行，这是有问题的
                if (buf->ReadAbleSize() > MAX_LINE) {
                    _recv_statu = RECV_HTTP_ERROR;
                    _resp_statu = 414; // URI TOO LONG
                    return false;
                }
                // 等数据的到来
                return true;
            }
            if (line.size() > MAX_LINE) {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_statu = 414;//URI TOO LONG
                return false;
            }
            bool ret = ParseHttpLine(line);
            if (ret == false) { return false; }
            // 首行处理完毕，进入头部获取阶段
            _recv_statu = RECV_HTTP_HEAD;
            return true;
        }

        bool RecvHttpHead(Buffer *buf) {
            if (_recv_statu != RECV_HTTP_HEAD) return false;
            // 一行一行取出数据，直到遇到空行为止，头部的格式key：val\r\nkey: val\r\n
            while (1) {
                std::string line = buf->GetLineAndPop();
                if (line.size() == 0) {
                    //缓冲区中的数据不足一行，则需要判断缓冲区的可读数据长度，如果很长了都不足一行，这是有问题的
                    if (buf->ReadAbleSize() > MAX_LINE) {
                        _recv_statu = RECV_HTTP_ERROR;
                        _resp_statu = 414;//URI TOO LONG
                        return false;
                    }
                    //缓冲区中数据不足一行，但是也不多，就等等新数据的到来
                    return true;
                }
                if (line.size() > MAX_LINE) {
                    _recv_statu = RECV_HTTP_ERROR;
                    _resp_statu = 414;
                    return false;
                }
                if (line == "\n" || line == "\r\n") {
                    break;
                }
                bool ret = ParseHttpHead(line);
                if (ret == false) {
                    return false;
                }
            }
            _recv_statu = RECV_HTTP_BODY;
            return true;
        }
        bool ParseHttpHead(std::string &line) {
            if (line.back() == '\n') line.pop_back();
            if (line.back() == '\r') line.pop_back();
            size_t pos = line.find(": ");
            if (pos == std::string::npos) {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_statu = 400; // BAD REQUEST
                return false;
            }
        }
        bool RecvHttpBody(Buffer *buf) {
            if (_recv_statu != RECV_HTTP_BODY) return false;
            size_t content_length = _request.ContentLength();
            if (content_length == 0) {
                _recv_statu = RECV_HTTP_OVER;
                return true;
            }
            size_t real_len = content_length - _request._body.size(); // 实际还需要接收的正文长度
            //3. 接收正文放到body中，但是也要考虑当前缓冲区中的数据，是否是全部的正文
            //  3.1 缓冲区中数据，包含了当前请求的所有正文，则取出所需的数据
            if (buf->ReadAbleSize() >= real_len) {
                _request._body.append(buf->ReadPosition(), real_len);
                buf->MoveReadOffset(real_len);
                _recv_statu = RECV_HTTP_OVER;
                return true;
            }
             //  3.2 缓冲区中数据，无法满足当前正文的需要，数据不足，取出数据，然后等待新数据到来
            _request._body.append(buf->ReadPosition(), buf->ReadAbleSize());
            buf->MoveReadOffset(buf->ReadAbleSize());
            return true;
        }
    public:
        HttpContext():_resp_statu(200), _recv_statu(RECV_HTTP_LINE) {}
        void ReSet() {
            _resp_statu = 200;
            _recv_statu = RECV_HTTP_LINE;
            _request.ReSet();
        }
        int RespStatu() { return _resp_statu; }
        HttpRecvStatu RecvStatu() { return _recv_statu; }
        HttpRequest &Request() { return _request; }
        void RecvHttpRequest(Buffer *buf) {
            //不同的状态，做不同的事情，但是这里不要break， 因为处理完请求行后，应该立即处理头部，而不是退出等新数据
            switch(_recv_statu) {
                case RECV_HTTP_LINE: RecvHttpLine(buf);
                case RECV_HTTP_HEAD: RecvHttpHead(buf);
                case RECV_HTTP_BODY: RecvHttpBody(buf);
            }
            return ;
        }
};  


class HttpServer {
    private:
        using Handler = std::function<void(const HttpRequest &, HttpResponse *)>;
        using Handlers = std::vector<std::pair<std::regex, Handler>>;
        Handlers _get_route;
        Handlers _post_route;
        Handlers _put_route;
        Handlers _delete_route;
        std::string _basedir; // 静态资源根目录
        TcpServer _server;
    private:
        void ErrorHandler(const HttpRequest &rep, HttpResponse *rsp) {
            // 组织一个错误的展示页面
            std::string body;
            body += "<html>";
            body += "<head>";
            body += "<meta http-equiv='Content-Type' content='text/html;charset=utf-8'>";
            body += "</head>";
            body += "<body>";
            body += "<h1>";
            body += std::to_string(rsp->_statu);
            body += " ";
            body += Util::StatuDesc(rsp->_statu);
            body += "</h1>";
            body += "</body>";
            body += "</html>";
            rsp->SetContent(body, "text/html");
        }
        // 将HttpResponse中的要素按照http协议格式进行组织，发送
        void WriteReponse(const PtrConnection &conn, const HttpRequest &req, HttpResponse &rsp) {
            //1.先完善头部字段
            if (req.Close() == true) {
                rsp.SetHeader("Connection", "close");
            }else {
                rsp.SetHeader("Connection", "keep-alive");
            }
            if (rsp._body.empty() == false && rsp.HasHeader("Content-Length") == false) {
                rsp.SetHeader("Content-Length", std::to_string(rsp._body.size()));
            }
            if (rsp._body.empty() == false && rsp.HasHeader("Content-Type") == false) {
                rsp.SetHeader("Content-Type", "application/octet-stream");
            }
            if (rsp._redirect_flag == true) {
                rsp.SetHeader("Location", rsp._redirect_url);
            }
            // 2.将rsp中的要素，按照http协议格式进行组织
            std::stringstream rsp_str;
            rsp_str << req._version << " " << std::to_string(rsp._statu) << " " << Util::StatuDesc(rsp._statu) << "\r\n";
            for (auto &head : rsp._headers) {
                rsp_str << head.first << ": " << head.second << "\r\n";
            }
            rsp_str << "\r\n";
            rsp_str << rsp._body;
            // 发送数据
            conn->Send(rsp_str.str().c_str(), rsp_str.str().size());
        }
        bool IsFileHandler(const HttpRequest &req) {
            // 必须设置了静态资源根目录
            if (_basedir.empty()) {
                return false;
            }
            // 请求方法，必须是GET / HEAD请求方法
            if (req._method != "GET" && req._method != "HEAD") {
                return false;
            }
            // 请求的资源路径必须是一个合法路径
            if (Util::VaildPath(req._path) == false) {
                return false;
            }
            // 请求的资源必须存在，且是一个普通文件
            // 有一种比较特殊，目录：/，/image/，这种情况后边默认追加一个index.html
            // 不要忘了前缀的相对根目录,也就是将请求路径转换为实际存在的路径  /image/a.png  ->   ./wwwroot/image/a.png
            std::string req_path = _basedir + req._path;
            if (req._path.back() == '/') {
                req_path += "index.html";
            }
            if (Util::IsRegular(req_path) == false) {
                return false;
            }
            return true;
        }
        //静态资源的请求处理 --- 将静态资源文件的数据读取出来，放到rsp的_body中，并设置mime
        void FileHandlder(const HttpRequest &req, HttpResponse *rsp) {
            std::string req_path = _basedir + req._path;
            if (req_path.back() == '/') {
                req_path += "index.html";
            }
            bool ret - Util::ReadFile(req_path, &rsp->_body);
            if (ret == false) {
                return ;
            }
            std::string mime = Util::ExtMime(req_path);
            rsp->SetHeader("Content-Type", mime);
            return ;
        }
        功能性请求的分类处理
        void Dispatcher(HttpRequest &req, HttpResponse *rsp, Handlers *handlers) {
            // 在对应请求方法的路由表中，查找是否含有对应资源请求的处理函数，有则调用，没有则404
            // 思想：路由表存储的
        }
}
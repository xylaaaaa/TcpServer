#ifndef __M_SERVER_H__
#define __M_SERVER_H__
#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <ctime>
#include <functional>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <typeinfo>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL DBG

#define LOG(level, format, ...) do{\
    if (level < LOG_LEVEL) break;\
    time_t t = time(NULL);\
    struct tm *ltm = localtime(&t);\
    char tmp[32] = {0};\
    strftime(tmp, 31, "%H:%M:%S", ltm);\
    fprintf(stdout, "[%p %s %s:%d] " format "\n", (void*)pthread_self(), tmp, __FILE__, __LINE__, ##__VA_ARGS__);\
}while(0)

#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__)
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)

#define BUFFER_DEFAULT_SIZE 1024
class Buffer {
    private:
        std::vector<char> _buffer;
        uint64_t _readr_idx;
        uint64_t _writer_idx;
    public:
        Buffer():_readr_idx(0), _writer_idx(0), _buffer(BUFFER_DEFAULT_SIZE){}
        char *Begin() { return &*_buffer.begin(); } // 返回的是一个迭代器并不是指针，所以要&*
        char *WritePosision() { return Begin() + _writer_idx; }
        char *ReadPosision() { return Begin() + _readr_idx; }
        uint64_t TailIdleSize() { return _buffer.size() - _writer_idx; }
        uint64_t HeadIdleSize() { return _readr_idx; }
        uint64_t ReadAbleSize() { return _writer_idx - _readr_idx; }
        // 将读偏移向后移动
        void MoveReadOffset(uint64_t len) {
            if (len == 0) return;
            assert(len <= ReadAbleSize());
            _readr_idx += len;
        }

        void MoveWriterOffset(uint64_t len) {
            assert(len <= TailIdleSize());
            _writer_idx += len;
        }

        void EnsureWriterSpace(uint64_t len) {
            if (TailIdleSize() >= len) return;
            // 空间大小够
            if (len <= TailIdleSize() + HeadIdleSize()) {
                uint64_t rsz = ReadAbleSize(); // 当前数据大小
                std::copy(ReadPosision(), ReadPosision() + rsz, Begin());
                _readr_idx = 0;
                _writer_idx = rsz;
            } else {
                DBG_LOG("RESIZE %ld", _writer_idx + len);
                _buffer.resize(_writer_idx + len);
            }
        }

        void Write(const void *data, uint64_t len) {
            if (len == 0) return;
            EnsureWriterSpace(len);
            const char *d = (const char *)data;
            std::copy(d, d + len, WritePosision());
        }

        void WriteAndPush(const void *data, uint64_t len) {
            Write(data, len);
            MoveWriterOffset(len);
        }

        void WriteString(const std::string &data) {
            return Write(data.c_str(), data.size());
        }

        void WriteStringAndPush(const std::string &data) {
            WriteString(data);
            MoveWriterOffset(data.size());
        }

        void WriteBuffer(Buffer &data) {
            return Write(data.ReadPosision(), data.ReadAbleSize());
        }

        void WriteBufferAndPush(Buffer &data) {
            WriteBuffer(data);
            MoveWriterOffset(data.ReadAbleSize());
        }
        // 读取
        void Read(void *buf, uint64_t len) {
            assert(len <= ReadAbleSize());
            std::copy(ReadPosision(), ReadPosision() + len, (char*)buf);
        }

        void ReadAndPop(void *buf, uint64_t len) {
            Read(buf, len);
            MoveReadOffset(len);
        }

        std::string ReadAsString(uint64_t len) {
            assert(len <= ReadAbleSize());
            std::string str;
            str.resize(len);
            Read(&str[0], len);
            return str;
        }

        std::string ReadAsStringAndPop(uint64_t len) {
            assert(len <= ReadAbleSize());
            std::string str = ReadAsString(len);
            MoveReadOffset(len);
            return str;
        }
        // 查找 \r \n
        char *FindCRLF() {
            char *res = (char*)memchr(ReadPosision(), '\n', ReadAbleSize());
            return res;
        }

        std::string GetLine() {
            char *pos = FindCRLF();
            if (pos == NULL) { return ""; }
            return ReadAsString(pos - ReadPosision() + 1);
        }

        std::string GetLineAndPop() {
            std::string str = GetLine();
            MoveReadOffset(str.size());
            return str;
        }

        void Clear() {
            _readr_idx = 0;
            _writer_idx = 0;
        }
};

#define MAX_LISTEN 1024
class Socket {
    private:   
        int _sockfd;
    public:
        Socket():_sockfd(-1){}
        Socket(int fd): _sockfd(fd) {}
        ~Socket() { Close(); }
        int Fd() { return _sockfd; }
        bool Create() {
            _sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (_sockfd < 0) {
                ERR_LOG("CREATE SOCKET FAILED!!");
                return false;
            }
            return true;
        }
        bool Bind(const std::string &ip, uint64_t port) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(ip.c_str());
            socklen_t len = sizeof(struct sockaddr_in);
            int ret = bind(_sockfd, (struct sockaddr*)&addr, len);
            if (ret < 0) {
                ERR_LOG("BIND ADDRESS FAILED!");
                return false;
            }
            return true;
        }

        bool Listen(int backlog = MAX_LISTEN) {
            int ret = listen(_sockfd, backlog);
            if (ret < 0) {
                ERR_LOG("SOCKET LISTEN FAILED!");
                return false;
            }
            return true;
        } 
        
        bool Connect(const std::string &ip, uint16_t port) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(ip.c_str());
            socklen_t len = sizeof(struct sockaddr_in);
            int ret = connect(_sockfd, (struct sockaddr*)&addr, len);
            if (ret < 0) {
                ERR_LOG("CONNECT SERVER FAILED!");
                return false;
            }
            return true;
        }

        int Accept() {
            int newfd = accept(_sockfd, NULL, NULL);
            if (newfd < 0) {
                ERR_LOG("SOCKET ACCEPT FAILED!");
                return -1;
            }
            return newfd;
        }

        ssize_t Recv(void *buf, size_t len, int flag = 0) {
            ssize_t ret = recv(_sockfd, buf, len, flag);
            if (ret <= 0) {
                //EAGAIN 当前socket的接收缓冲区中没有数据了，在非阻塞的情况下才会有这个错误
                //EINTR  表示当前socket的阻塞等待，被信号打断了，
                if (errno == EAGAIN || errno == EINTR) {
                    return 0;//表示这次接收没有接收到数据
                }
                ERR_LOG("SOCKET RECV FAILED!!");
                return -1;
            }
            return ret;
        }

        ssize_t NonBlockRecv(void *buf, size_t len) {
            return Recv(buf, len, MSG_DONTWAIT); // MSG_DONTWAIT 表示当前接收为非阻塞。
        }

        ssize_t Send(const void *buf, size_t len, int flag = 0) {
            ssize_t ret = send(_sockfd, buf, len, flag);
            if (ret < 0) {
                if (errno == EAGAIN || errno == EINTR) {
                    return 0;
                }
                ERR_LOG("SOCKET SEND FAILED!!");
                return -1;
            }
            return ret;
        }

        ssize_t NonBlockSend(void *buf, size_t len, int flag = MSG_DONTWAIT);

        void Close() {
            if (_sockfd != -1) {
                close(_sockfd);
                _sockfd = -1;
            }
        }

        

};

class Poller;
class EventLoop;
class Channel {
    private:
        int _fd;
        EventLoop *_loop;
        uint32_t _events; // 当前需要监控的事件
        uint32_t _revents;// 当前连接触发的事件
        using Eventcallback = std::function<void()>;
        Eventcallback _read_callback;  // 可读事件被触发的回调函数
        Eventcallback _write_callback; // 可写事件被触发的回调函数
        Eventcallback _error_callback; // 错误事件被触发的回调函数
        Eventcallback _close_callback; // 连接断开被触发的回调函数
        Eventcallback _event_callback; // 任意事件被触发的回调函数
    
    public:
        Channel(EventLoop *loop, int fd) : _fd(fd), _events(0), _revents(0), _loop(loop) {}
        int Fd() { return _fd; }
        uint32_t Events() { return _events; } // 获取想要监控的事件
        void SetREvents(uint32_t events) { _revents = events; } // 设置实际就绪的事件
        void SetReadCallback(const Eventcallback &cb) { _read_callback = cb; }
        void SetWriteCallback(const Eventcallback &cb) { _write_callback = cb; }
        void SetErrorCallback(const Eventcallback &cb) { _error_callback = cb; }
        void SetCloseCallback(const Eventcallback &cb) { _close_callback = cb; }
        void SetEventCallback(const Eventcallback &cb) { _event_callback = cb; }
        // 当前是否监控了可读
        bool ReadAble() { return ( _events & EPOLLIN); }
        // 可写
        bool WriteAble() { return (_events & EPOLLOUT); }
        // 启动读事件监控
        void EnableRead() { _events |= EPOLLIN; Update(); }
        // 写
        void EnableWrite() { _events |= EPOLLOUT; Update(); }
        // 关闭写事件监控
        void DisableRead() { _events &= ~EPOLLIN; Update(); }
        // 写
        void DisableWrite() { _events &= ~EPOLLOUT; Update(); }
        // 关闭所有事件
        void DisableAll() { _events = 0; Update(); }
        // 移除监控
        void Remove();
        void Update();
        // 事件处理，一旦连接出发了事件， 就调用这个函数， 自己触发了什么事件如何处理自己决定
        void HandleEvent() {
            if ((_revents & EPOLLIN) || (_revents & EPOLLRDHUP) || (_revents & EPOLLPRI)) {
                // 不管任何事件，都调用的回调函数
                if (_read_callback) _read_callback();
            }
            // 有可能会释放连接的操作事件，一次只处理一个
            if (_revents & EPOLLOUT) {
                if (_write_callback) _write_callback();
            } else if (_revents & EPOLLERR) {
                if (_error_callback) _error_callback(); //一旦出错，就会释放连接，因此要放到前边调用任意回调
            }else if (_revents & EPOLLHUP) {
                if (_close_callback) _close_callback();
            }
            if (_event_callback) _event_callback();
        }
};

#define MAX_EPOLLEVENTS 1024
class Poller {
    private:
        int _epfd;
        struct epoll_event _evs[MAX_EPOLLEVENTS];
        std::unordered_map<int, Channel*> _channels;
    private:    
        void Update(Channel *channel, int op) {
            // int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
            int fd = channel->Fd();
            struct epoll_event ev;
            ev.data.fd = fd;
            ev.events = channel->Events();
            int ret = epoll_ctl(_epfd, op, fd, &ev);
            if (ret < 0) {
                ERR_LOG("EPOLLCTL FAILED");
            }
            return;
        }
        // 判断一个Channel是否已经添加了事件监控
        bool HasChannel(Channel *channel) {
            auto it = _channels.find(channel->Fd());
            if (it == _channels.end()) {
                return false;
            }
            return true;
        }
    public:
        Poller() {
            _epfd = epoll_create(MAX_EPOLLEVENTS);
            if (_epfd < 0) {
                ERR_LOG("EPOLL CREATE FAILED");
                abort();
            }
        }

        void UpdateEvent(Channel *channel) {
            bool ret = HasChannel(channel);
            if (ret == false) {
                _channels.insert(std::make_pair(channel->Fd(), channel));
                return Update(channel, EPOLL_CTL_ADD);
            }
            return Update(channel, EPOLL_CTL_MOD);
        }
        // 移除监控
        void RemoveEvent(Channel *channel) {
            auto it = _channels.find(channel->Fd());
            if (it != _channels.end()) {
                _channels.erase(it);
            }
            Update(channel, EPOLL_CTL_DEL);
        }
        // 开始监控，返回活跃连接
        void Poll(std::vector<Channel*> *active) {
            // int epoll_wait(int epfd, struct epoll_event *evs, int maxevevts, int timeout);
            int nfds = epoll_wait(_epfd, _evs, MAX_EPOLLEVENTS, -1);
            if (nfds < 0) {
                // 系统调用被信号中断
                if (errno == EINTR) {
                    return ;
                }
                ERR_LOG("EPOLL WAIT ERROR:%s\n", strerror(errno));
                abort();//退出程序
            }
            // struct epoll_event {
            //     uint32_t events;    // epoll事件类型
            //     epoll_data_t data;  // 用户数据
            // };
            // typedef union epoll_data {
            //     void    *ptr;       // 指针
            //     int      fd;        // 文件描述符
            //     uint32_t u32;       // 32位整数
            //     uint64_t u64;       // 64位整数
            // } epoll_data_t;
            for (int i = 0; i < nfds; i++) {
                auto it = _channels.find(_evs[i].data.fd);
                assert(it != _channels.end());
                it->second->SetREvents(_evs[i].events);
                active->push_back(it->second);
            }
            return;
        }
};

using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;
class TimerTask {
    private:
        uint64_t _id;
        uint32_t _timeout;
};

class TimerWheel {};

class EventLoop {
    private:
        using Functor = std::function<void()>;
        std::thread::id _thread_id; // 线程ID
        int _event_fd; // eventid唤醒IO事件监控有可能导致的阻塞，一个轻量级的事件通知机制
        std::unique_ptr<Channel> _event_channel;
        Poller _poller; // 对所有描述符的事件监控
        std::vector<Functor> _tasks; // 任务池
        std::mutex _mutex; // 实现任务池操作的线程安全
        TimerWheel _timer_wheel; //定时器模块
    public:
        // 执行任务池中的所有任务
        void RunAllTask() {
            std::vector<Functor> functor;
            {
                std::unique_lock<std::mutex> _lock(_mutex);
                _tasks.swap(functor);
            }
            for (auto &f : functor) {
                f();
            }
            return ;
        }

        static int CreateEventFd() {
            // _1：计时器的初始值
            // _2：标志位参数 EFD_CLOEXEC（执行exec（）系列调用时自动关闭该fd，防止子进程继承fd，提升安全性）  
            // EFD_NONBLOCK（非阻塞）
            int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK); 
            if (efd < 0) {
                ERR_LOG("CREATE EVENTFD FAILED");
                abort();
            }
            return efd;
        }
        
        void ReadEventfd() {
            uint64_t res = 0;
            int ret = read(_event_fd, &res, sizeof(res));
            if (ret < 0) {
                //EINTR -- 被信号打断；   EAGAIN -- 表示无数据可读
                if (errno == EINTR || errno == EAGAIN) {
                    return;
                }
                ERR_LOG("READ EVENTFD FAILED!");
                abort();
            }
            return ;
        }

        void WeakUpEventFd() {
            uint64_t val = 1;
            int ret = write(_event_fd, &val, sizeof(val));
            if (ret < 0) {
                if (errno == EINTR) {
                    return;
                }
                ERR_LOG("READ EVENTFD FAILED!");
                abort();
            }
            return ;
        }
    public:
        EventLoop() :_thread_id(std::this_thread::get_id()),
                    _event_fd(CreateEventFd()),
                    _event_channel(new Channel(this, _event_fd)),
                    _timer_wheel(this) {
            // 给eventfd添加可读事件回调函数，读取eventfd事件通知次数
            _event_channel->SetReadCallback(std::bind(&EventLoop::ReadEventfd, this));
            // 启动eventfd
            _event_channel->EnableRead();            
        }

        void start() {
            while (1) {
                // 事件监控
                std::vector<Channel *> actives;
                _poller.Poll(&actives);
                // 事件处理
                for (auto &channel : actives) {
                    channel->HandleEvent();
                } 
                // 执行任务
                RunAllTask();
            }
        }
        // 判断当前线程是否是EventLoop对应的线程
        bool IsInLoop() {
            return (_thread_id == std::this_thread::get_id());
        }

        void AssertInLoop() {
            assert(_thread_id == std::this_thread::get_id());
        }

        void RunInLoop(const Functor &cb) {
            if (IsInLoop()) {
                return cb();
            }
            return QueueInLoop(cb);
        }

        void QueueInLoop(const Functor &cb) {
            {
                std::unique_lock<std::mutex> _lock(_mutex);
                _tasks.push_back(cb);
            }
            //唤醒有可能因为没有事件就绪，而导致的epoll阻塞；
            //其实就是给eventfd写入一个数据，eventfd就会触发可读事件
            WeakUpEventFd();
        }
        // 添加/修改描述符的事件监控
        void UpdateEvent(Channel *channel) { return _poller.UpdateEvent(channel); }
        //移除描述符的监控
        void RemoveEvent(Channel *channel) { return _poller.RemoveEvent(channel); }
};

#endif
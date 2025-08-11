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
        // 事件处理，一旦连接触发了事件， 就调用这个函数， 自己触发了什么事件如何处理自己决定
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
        int _epfd; // epoll实例文件描述符
        struct epoll_event _evs[MAX_EPOLLEVENTS]; // 用于存储epoll_wait()返回的就绪时间
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
        bool _canceled;
        TaskFunc _task_cb;
        ReleaseFunc _release;
    public:
        TimerTask(uint64_t id, uint32_t delay, const TaskFunc &cb):
            _id(id), _timeout(delay), _task_cb(cb), _canceled(false) {}
        ~TimerTask() {
            if (_canceled == false) {
                _task_cb();
            }
            ReleaseFunc _release;
        }
        void Cancel() { _canceled = true; }
        void SetRelease(const ReleaseFunc &cb) {_release = cb; }
        uint32_t DelayTime() { return _timeout; }
};

class TimerWheel {
    private:
        using WeakTask = std::weak_ptr<TimerTask>;
        using PtrTask = std::shared_ptr<TimerTask>;
        int _tick;
        int _capacity;
        std::vector<std::vector<PtrTask>> _wheel;
        std::unordered_map<uint64_t, WeakTask> _timers;

        EventLoop *_loop;
        int _timerfd;
        std::unique_ptr<Channel> _timer_channel;
    private:
        void RemoveTimer(uint64_t id) {
            auto it = _timers.find(id);
            if (it != _timers.end()) {
                _timers.erase(it);
            }
        }

        static int CreateTimerfd() {
            int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
            if (timerfd < 0) {
                ERR_LOG("TIMERFD CREATE FAILED");
            }
            // int timerfd_settime(int fd, int flags, struct itimerspec *new, struct itimerspec *old);
            struct itimerspec itime;
            itime.it_value.tv_sec = 1;
            itime.it_value.tv_nsec = 0; // 第一次超时时间为1s后
            itime.it_interval.tv_sec = 1;
            itime.it_interval.tv_nsec = 0; // 第一次超时后，每次超时的间隔时间
            timerfd_settime(timerfd, 0, &itime, NULL);
            return timerfd;
        }

        int ReadTimefd() {
            uint64_t times;
            //有可能因为其他描述符的事件处理花费事件比较长，然后在处理定时器描述符事件的时候，有可能就已经超时了很多次
            //read读取到的数据times就是从上一次read之后超时的次数
            int ret = read(_timerfd, &times, 8);
            if (ret < 0) {
                ERR_LOG("READ TIMEFD FAILED");
                abort();
            }
            return times;
        }

        void RunTimerTask() {
            _tick = (_tick + 1) % _capacity;
            _wheel[_tick].clear();
        }

        void OnTime() {
            // 根据实际的超时的次数，执行对应的超时任务
            int times = ReadTimefd();
            for (int i = 0; i < times; i++) {
                RunTimerTask();
            }
        }

        void TimerAddInLoop(uint64_t id, uint32_t delay, const TaskFunc &cb) {
            PtrTask pt(new TimerTask(id, delay, cb));
            pt->SetRelease(std::bind(&TimerWheel::RemoveTimer, this, id)); 
            int pos = (_tick + delay) & _capacity;
            _wheel[pos].push_back(pt);
            _timers[id] = WeakTask(pt);
        }

        void TimerRefreshInLoop(uint64_t id) {
            auto it = _timers.find(id);
            if (it == _timers.end()) {
                return;
            }
            Ptrtask pt = it->second.lock();
            int delay = pt->DelayTime();
            int pos = (_tick + delay) % _capacity;
            _wheel[pos].push_back(pt);
        }

        void TimerCancelInLoop(uint64_t id) {
            auto it = _timers.find(id);
            if (it == timers.end()) {
                return;
            }
            PtrTask pt = it->second.lock();
            if (pt) pt->Cancel();
        }
    public:
        TimerWheel(EventLoop *loop):_capacity(60), _tick(0), _wheel(_capacity), _loop(loop),
            _timefd(CreateTimerfd()), _timer_channel(new Channel(_loop, _timerfd)) {
                _timer_channel->SetReadCallback(std::bind(&TimerWheel::Ontime, this));
                _timer_channel->EnableRead(); 启动读事件监控
            }
        // 定时器中有个_timers成员，定时器信息的操作有可能在多线程中进行，因此需要考虑线程安全问题
        // 如果不想加锁，那就把对定期的所有操作，都放到一个线程中进行
        void TimerAdd(uint16_t id, uint32_t delay, const TaskFunc &cb);
        void TimerRefresh(uint64_t id);
        void TimerCancel(uint64_t id);
        /*这个接口存在线程安全问题--这个接口实际上不能被外界使用者调用，只能在模块内，在对应的EventLoop线程内执行*/
        bool HasTimer(uint64_t id) {
            auto it = _timers.find(id);
            if (it == _timers.end()) {
                return false;
            }
            return true;
        }
};

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
        void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) { return _timer_wheel.TimerAdd(id, delay, cb); }
        void TimerRefresh(uint64_t id) { return _timer_wheel.TimerRefresh(id); }
        void TimerCancel(uint64_t id) { return _timer_wheel.TimerCancel(id); }
        bool HasTimer(uint64_t id) { return _timer_wheel.HasTimer(id); }
};

class Connection;
//DISCONECTED -- 连接关闭状态；   CONNECTING -- 连接建立成功-待处理状态
//CONNECTED -- 连接建立完成，各种设置已完成，可以通信的状态；  DISCONNECTING -- 待关闭状态
typedef enum {DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING}ConnStatu;
using PtrConnection = std::shared_ptr<Connection>;
class Connection : public std::enable_shared_from_this<Connection> {
    private:
        uint64_t _conn_id; // 连接的唯一ID，便于连接的管理和查找
        // uint64_t _timer_id; // 定时器ID，必须是唯一的，这块为了简化操作使用conn_id作为定时器ID
        int _sockfd; // 连接关联的文件描述符
        bool _enable_inactive_release; // 是否启用非活跃销毁的判断标志，默认为false
        EventLoop *_loop; // 连接所关联的一个EventLoop
        ConnStatu _statu; // 连接状态
        Socket _socket; // 套接字操作管理
        Channel _channel; // 连接的时间管理
        Buffer _in_buffer; // 输入缓冲区---存放从socket中读取到的数据
        Buffer _out_buffer; // 输出缓冲区---存放要发送给对端的数据
        Any _context; // 请求的接收处理上下文

        /*这四个回调函数，是让服务器模块来设置的（其实服务器模块的处理回调也是组件使用者设置的）*/
        /*换句话说，这几个回调都是组件使用者使用的*/
        using ConnectedCallback = std::function<void(const PtrConnection&)>;
        using MessageCallback = std::function<void(const PtrConnection&, Buffer*)>;
        using ClosedCallback = std::function<void(const PtrConnection&)>;
        using AnyEventCallback = std::function<void(const PtrConnection&)>;
        ConnectedCallback _connected_callback;
        MessageCallback _message_callback;
        ClosedCallback _closed_callback;
        AnyEventCallback _event_callback;
        /*组件内的连接关闭回调--组件内设置的，因为服务器组件内会把所有的连接管理起来，一旦某个连接要关闭*/
        /*就应该从管理的地方移除掉自己的信息*/
        ClosedCallback _server_closed_callback;
    private:
        // 五个Channel的事件回调函数
        // 描述符可读事件触发后调用的函数，接收socket数据放到接收缓冲区中，然后调用_message_callback
        void HandleRead() {
            char buf[65536];
            ssize_t ret = _socket.NonBlockRecv(buf, 65536); 
            if (ret < 0) {
                return ShutdownInLoop();
            }
            // 将数据放入输入缓冲区，写入之后顺便将写偏移向后移动
            _in_buffer.WriteAndPush(buf, ret);
            if (_in_buffer.ReadAbleSize() > 0) {
                //shared_from_this--从当前对象自身获取自身的shared_ptr管理对象
                return _message_callback(shared_from_this(), &_in_buffer);
            }
        }

        void HandleWrite() {
            ssize_t ret = _socket.NonBlockSend(_out_buffer.ReadPosision(), _out_buffer.ReadAbleSize());
            if (ret < 0) {
                // 发送错误就该关闭连接了
                if (_in_buffer.ReadAbleSize() > 0) {
                    _message_callback(shared_from_this(), &_in_buffer);
                }
                return Release();
            }
            _out_buffer.MoveReadOffset(ret);
            if (_out_buffer.ReadAbleSize() == 0) {
                _channel.DisableWrite(); //没有数据发送了，将读偏移向后移动
                //如果当前是连接待关闭状态，则有数据，发送完数据释放连接，没有数据则直接释放
                if (_statu == DISCONNECTING) {
                    return Release();
                }
            }
            return;
        }

        void HandleClose() {
            if (_in_buffer.ReadAbleSize() > 0) {
                _message_callback(shared_from_this(), &_in_buffer);
            }
            return Release();
        }

        void HandleError() {
            return HandleClose();
        }

        void HandleEvent() {
            if (_enable_inactive_release == true) { _loop->TimerRefresh(_conn_id); }
            if (_event_callback) { _event_callback(shared_from_this()); }
        }
        //连接获取之后，所处的状态下要进行各种设置（启动读监控,调用回调函数）
        void EstablishedInLoop() {
            assert(_statu == CONNECTING);
            _statu = CONNECTED; //当前函数执行完毕，则连接进入已完成连接状态
            // 一旦启动读事件监控就有可能会立即触发读事件，如果这时候启动了非活跃连接销毁
            _channel.EnableRead();
            if (_connected_callback) _connected_callback(shared_from_this());
        }
        //这个接口才是实际的释放接口
        void ReleaseInLoop() {
            _statu = DISCONNECTED;
            _channel.Remove();
            _socket.Close();
            //  如果当前定时器队列中还有定时销毁任务，则取消任务
            if (_loop->HasTimer(_conn_id)) CancelInactiveReleaseInLoop();
            // 调用关闭回调函数，避免先移除服务器管理的连接信息导致Connection被释放，再去处理会出错，因此先调用用户的回调函数
            if (_closed_callback) _close_callback(shared_from_this());
            //移除服务器内部管理的连接信息
            if (_server_closed_callback) _server_closed_callback(shared_from_this());
        }
        //这个关闭操作并非实际的连接释放操作，需要判断还有没有数据待处理，待发送
        void ShutdownInLoop() {
            _statu = DISCONNECTING;
            if (_in_buffer.ReadAbleSize() > 0) {
                if (_message_callback) _message_callback(shared_from_this(), &_in_buffer);
            }

            if (_out_buffer.ReadAbleSize() > 0) {
                if (_channel.WriteAble() == false) {
                    _channel.EnableWrite();
                }
            }
            if (_out_buffer.ReadAbleSize() == 0) {
                Release();
            }
        }

        void EnableInactiveReleaseInLoop(int sec) {
            //1. 将判断标志 _enable_inactive_release 置为true
            _enable_inactive_release = true;
             //2. 如果当前定时销毁任务已经存在，那就刷新延迟一下即可
            if (_loop->HasTimer(_conn_id)) {
                return _loop->TimerRefresh(_conn_id);
            }
            _loop->TimerAdd(_conn_id, sec, std::bind(&Connection::Release, this));
        }

        void CancelInactiveReleaseInLoop() {
            _enable_inactive_release = false;
            if (_loop->HasTimer(_conn_id)) { 
                _loop->TimerCancel(_conn_id); 
            }
        }

        void UpgradeInLoop(const Any &context, 
                const ConnectedCallback &conn, 
                const MessageCallback &msg, 
                const ClosedCallback &closed, 
                const AnyEventCallback &event) {
            _context = context;
            _connected_callback = conn;
            _message_callback = msg;
            _closed_callback = closed;
            _event_callback = event;
        }
    public:
        Connection(EventLoop *loop, uint64_t conn_id, int sockfd):_conn_id(conn_id), _sockfd(sockfd),
            _enable_inactive_release(false), _loop(loop), _statu(CONNECTING), _sockfd(_sockfd),
            _channel(loop, _sockfd) {
                _channel.SetCloseCallback(std::bind(&Connection::HandleClose, this));
                _channel.SetEventCallback(std::bind(&Connection::HandleEvent, this));
                _channel.SetReadCallback(std::bind(&Connection::HandleRead, this));
                _channel.SetWriteCallback(std::bind(&Connection::HandleWrite, this));
                _channel.SetErrorCallback(std::bind(&Connection::HandleError, this));
        }
        ~Connection() { DBG_LOG("RELEASE CONNECTION:%p", this); }
        //获取管理的文件描述符
        int Fd() { return _sockfd; }
        //获取连接ID
        int Id() { return _conn_id; }
        bool Connected() { return (_statu == CONNECTED); }
        //设置上下文--连接建立完成时进行调用
        void SetContext( return &_context; )
        void SetConnectedCallback(const ConnectedCallback&cb) { _connected_callback = cb; }
        void SetMessageCallback(const MessageCallback&cb) { _message_callback = cb; }
        void SetClosedCallback(const ClosedCallback&cb) { _closed_callback = cb; }
        void SetAnyEventCallback(const AnyEventCallback&cb) { _event_callback = cb; }
        void SetSrvClosedCallback(const ClosedCallback&cb) { _server_closed_callback = cb; }
        // 发送数据，将数据发送到缓冲区，启动写事件
        void Send(const char* data, size_t len) {
            //外界传入的data，可能是个临时的空间，我们现在只是把发送操作压入了任务池，有可能并没有被立即执行
            //因此有可能执行的时候，data指向的空间有可能已经被释放了。
            Buffer buf;
            buf.WriteAndPush(data, len);
            _loop->RunInLoop(std::bind(&Connection::SendInLoop, this, std::move(buf)));
        }
        //提供给组件使用者的关闭接口--并不实际关闭，需要判断有没有数据待处理
        void Shutdown() {
            _loop->RunInLoop(std::bind(&Connection::ShutdownInLoop, this));
        }
        void Release() {
            _loop->QueueInLoop(std::bind(&Connection::ReleaseInLoop, this));
        }
         //启动非活跃销毁，并定义多长时间无通信就是非活跃，添加定时任务
         void EnableInactiveRelease(int sec) {
            _loop->RunInLoop(std::bind(&Connection::EnableInactiveReleaseInLoop, this, sec));
        }
        //取消非活跃销毁
        void CancelInactiveRelease() {
            _loop->RunInLoop(std::bind(&Connection::CancelInactiveReleaseInLoop, this));
        }
        //切换协议---重置上下文以及阶段性回调处理函数 -- 而是这个接口必须在EventLoop线程中立即执行
        //防备新的事件触发后，处理的时候，切换任务还没有被执行--会导致数据使用原协议处理了。
        void Upgrade(const Any &context, const ConnectedCallback &conn, const MessageCallback &msg, 
            const ClosedCallback &closed, const AnyEventCallback &event) {
            _loop->AssertInLoop();
            _loop->RunInLoop(std::bind(&Connection::UpgradeInLoop, this, context, conn, msg, closed, event));
        }
};

#endif
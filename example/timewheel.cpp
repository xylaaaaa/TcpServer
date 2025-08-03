#include <iostream>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <memory>
#include <unistd.h>

using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;

class TimerTask {
    private:
        uint64_t _id;
        uint32_t _timeout; // 定时任务的超时时间
        bool _canceled;
        TaskFunc _task_cb; // 定时器对象要执行的定时任务
        ReleaseFunc _release; // 用于删除TimerWheel中保存的定时器对象信息
    public:
        TimerTask(uint64_t id, uint32_t delay, const TaskFunc &cb) : 
            _id(id), _timeout(delay), _task_cb(cb), _canceled(false) {}

        ~TimerTask() {
            if (_canceled == false) _task_cb();
            _release();
        }
        void Cancel() {_canceled = true; }
        void SetRelease(const ReleaseFunc &cb) { _release = cb; }
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
    private:
        void RemoveTimer(uint64_t id) {
            auto it = _timers.find(id);
            if (it != _timers.end()) {
                _timers.erase(it);
            }
        }
    public:
        TimerWheel():_capacity(60), _tick(0), _wheel(_capacity) {}
        void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) {
            PtrTask pt(new TimerTask(id, delay, cb));
            pt->SetRelease(std::bind(&TimerWheel::RemoveTimer, this, id));
            int pos = (_tick + delay) % _capacity;
            _wheel[pos].push_back(pt);
            _timers[id] = WeakTask(pt);
        }

        void TimerRefresh(uint64_t id) {
            auto it = _timers.find(id);
            if (it == _timers.end()) {
                return;
            }
            PtrTask pt = it->second.lock();
            int delay = pt->DelayTime();
            int pos = (_tick + delay) % _capacity;
            _wheel[pos].push_back(pt);
        }

        void TimerCancel(uint64_t id) {
            auto it = _timers.find(id);
            if (it == _timers.end()) {
                return ;
            }
            PtrTask pt = it->second.lock(); // 如果对象没有被销毁返回一个shared_ptr，否则就返回空的shared_ptr
            if (pt) pt->Cancel();
        }
        void RunTimerTask() {
            _tick = (_tick + 1) % _capacity;
            _wheel[_tick].clear(); // 清空指定位置的数组，就会把数组中保存的所有管理定时器对象的shared_ptr释放掉

        }
};

class Test {
    public:
        Test() { std::cout << "析构" << std::endl; }
        ~Test() { std::cout << "析构" << std::endl; }
};

void DelTest(Test *t) {
    delete t;
}

int main() {
    TimerWheel tw;
    Test *t = new Test();
    tw.TimerAdd(5, 5, std::bind(DelTest, t));

    for (int i = 0; i < 5; i++) {
        sleep(1);
        tw.TimerRefresh(5);
        tw.RunTimerTask();
        std::cout << "刷新了一下定时任务，重新需要5s中后才会销毁\n";
    }
    //tw.TimerCancel(5);
    while(1) {
        sleep(1);
        std::cout << "-------------------\n";
        tw.RunTimerTask();//向后移动秒针
    }
    return 0;
}



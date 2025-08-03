#include <iostream>
#include <typeinfo>
#include <cassert>
#include <unistd.h>
#include <any>

class Any {
    private:
        class holder {
            public:
                virtual ~holder() {}
                virtual const std::type_info& type() = 0;
                virtual holder *clone() = 0;
        };
        template <typename T>
        class placeholder : public holder {
            public:
                placeholder(const T &val) : _val(val) {}
                virtual const std::type_info& type() { return typeid(T); }
                virtual holder *clone() { return new placeholder(_val); }
            public:
                T _val;
        };
        holder *_content;
    public:
        Any() : _content(NULL) {}
        template <class T>
        Any(const T &val) : _content(new placeholder<T>(val)) {}
        Any(const Any &other) : _content(other._content ? other._content->clone() : NULL) {}
        ~Any() { delete _content; }
        Any &swap(Any &other) {
            std::swap(_content, other._content);
            return *this;
        }
        template <class T>
        T *get() {
            assert(typeid(T) == _content->type());
            return &(static_cast<placeholder<T>*>(_content)->_val);
        }
        template <class T>
        Any& operator=(const T &val) {
            Any(val).swap(*this);
            return *this;
        }
        Any& operator=(const Any &other) {
            Any(other).swap(*this);
            return *this;
        }
};

class Test {
    public:
        Test() {std::cout << "构造" << std::endl; }
        Test(const Test &t) {std::cout << "拷贝" << std::endl; }
        ~Test() {std::cout << "析构" << std::endl; }
};

int main() 
{
    // std::any a;
    // a = 10;
    // int *pi = std::any_cast<int>(&a);
    // std::cout << *pi << std::endl;

    // a = std::string("hello");
    // std::string *ps = std::any_cast<std::string>(&a);
    // std::cout << *ps << std::endl;
    // return 0;
    Any a;
    Test t;
    a = t;
    
    
    a = 10;
    int *pa = a.get<int>();
    std::cout << *pa << std::endl;
    a = std::string("nihao");
    std::string *ps = a.get<std::string>();
    std::cout << *ps << std::endl;
    
}
#include <pcap/pcap.h>
#include <utility>
#include <cassert>
#include <cstdlib>
#include <iostream>

namespace pcapcc
{
  namespace detail {

    [[noreturn]]
    inline void throw_error(const char *err, const char  *what)
    {
      std::clog << what << ": " << err << '\n';
      std::abort();
    }

    [[noreturn]]
    inline void throw_error(int err, pcap_t *p, const char *what)
    {
      pcap_perror(p, what);
      std::abort();
    }
  }

  class interface_iterator
  {
  public:
    using value_type = pcap_if_t;
    using reference = pcap_if_t const &;
    using pointer =  pcap_if_t const *;
    
    explicit interface_iterator(const pcap_if_t *iface)
      : if_{ iface }
    {
    }

    interface_iterator()
      : if_{ }
    {
    }

    interface_iterator& operator++()
    {
      if_ = if_->next;
      return *this;
    }

    interface_iterator operator++(int)
    {
      auto retv = *this;
      ++*this;
      return retv;
    }

    reference operator*() const
    {
      return *if_;
    }

    pointer operator->() const
    {
      return if_;
    }
    
  private:
    const pcap_if_t *if_;
  };

  inline bool operator==(const interface_iterator &x, const interface_iterator &y)
  {
    return x.operator->() == y.operator->();
  }

  inline bool operator!=(const interface_iterator &x, const interface_iterator &y)
  {
    return !(x == y);
  }
  
  
  class interface_list
  {
  public:
    using iterator = interface_iterator;
    
    explicit interface_list(pcap_if_t *list)
      : list_{ list }
    {
    }

    interface_list()
    {
      char errbuf[PCAP_ERRBUF_SIZE];
      if (pcap_findalldevs(&list_, errbuf)) {
	detail::throw_error(errbuf, __func__);
      }
    }

    ~interface_list() noexcept
    {
      ::pcap_freealldevs(list_);
    }

    iterator begin() const
    {
      return iterator{list_};
    }

    iterator end() const
    {
      return iterator{};
    }

  private:
    pcap_if_t *list_;
  };

  class warning
  {
  public:
    warning() = default;

    warning(int err, pcap_t *p, const char *what)
      : err_(err)
    {
    }

    explicit operator bool() const noexcept
    {
      return err_ != 0;
    }

  private:
    int err_{};
  };

  class handle
  {
  public:
    explicit handle(const char *source)
    {
      char errbuf[PCAP_ERRBUF_SIZE];
      if (!((p_ = ::pcap_create(source, errbuf)))) {
	detail::throw_error(errbuf, __func__);
      }
    }

    ~handle() noexcept
    {
      ::pcap_close(p_);
    }

    warning activate()
    {
      int r = ::pcap_activate(p_);
      if (r < 0) {
	detail::throw_error(r, p_, __func__);
      }

      return warning{ r, p_, __func__ };
    }

    

  private:
    pcap_t *p_;
  };
}


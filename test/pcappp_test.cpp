#include  "pcap.hpp"

int main()
{
  using namespace pcapcc;

  interface_list ifaces;
  for (auto const &i : ifaces) {
    std::cout << i.name << "\n";
  }

  handle h{ "eth0" };
  h.activate();
}

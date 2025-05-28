#ifndef NETFLOW_CORE_FLOW_TABLE_H_
#define NETFLOW_CORE_FLOW_TABLE_H_

#include <unordered_map>
#include <memory> // For potential future use with smart pointers
#include "netflow/core/flow.h"

namespace netflow {
namespace core {

class FlowTable {
 public:
  FlowTable();

  void add_flow(const Flow& flow, int action);
  bool remove_flow(const Flow& flow);
  bool get_flow_action(const Flow& flow, int& action_out) const;
  void clear_flows();

 private:
  std::unordered_map<Flow, int> flow_entries_;
};

}  // namespace core
}  // namespace netflow

#endif  // NETFLOW_CORE_FLOW_TABLE_H_

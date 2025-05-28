#include "netflow/core/flow_table.h"

namespace netflow {
namespace core {

FlowTable::FlowTable() {
  // Constructor can be empty if no special initialization is needed
  // for flow_entries_ beyond its default construction.
}

void FlowTable::add_flow(const Flow& flow, int action) {
  flow_entries_[flow] = action; // Adds or updates the entry
}

bool FlowTable::remove_flow(const Flow& flow) {
  return flow_entries_.erase(flow) > 0; // erase returns the number of elements removed
}

bool FlowTable::get_flow_action(const Flow& flow, int& action_out) const {
  auto it = flow_entries_.find(flow);
  if (it != flow_entries_.end()) {
    action_out = it->second;
    return true;
  }
  return false;
}

void FlowTable::clear_flows() {
  flow_entries_.clear();
}

}  // namespace core
}  // namespace netflow

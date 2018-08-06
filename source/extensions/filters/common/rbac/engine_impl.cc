#include "extensions/filters/common/rbac/engine_impl.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace RBAC {

RoleBasedAccessControlEngineImpl::RoleBasedAccessControlEngineImpl(
    const envoy::config::rbac::v2alpha::RBAC& rules)
    : allowed_if_matched_(rules.action() ==
                          envoy::config::rbac::v2alpha::RBAC_Action::RBAC_Action_ALLOW) {
  for (const auto& policy : rules.policies()) {
    //policies_.emplace_back(policy.second);
    policies_.insert(std::pair<std::string, PolicyMatcher>(policy.first, policy.second));
  }
}

bool RoleBasedAccessControlEngineImpl::allowed(
    const Network::Connection& connection, const Envoy::Http::HeaderMap& headers,
    const envoy::api::v2::core::Metadata& metadata,
    std::string& effectivePolicyID) const {
  bool matched = false;

  /*
  for (const auto& policy : policies_) {
    if (policy.matches(connection, headers, metadata)) {
      matched = true;
      break;
    }
  }*/

  for(auto it = policies_.begin(); it!=policies_.end(); it++) {
    if (it->second.matches(connection, headers, metadata)) {
      matched = true;
      effectivePolicyID = it->first;
      break;
    }
  }

  // only allowed if:
  //   - matched and ALLOW action
  //   - not matched and DENY action
  return matched == allowed_if_matched_;
}

} // namespace RBAC
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy

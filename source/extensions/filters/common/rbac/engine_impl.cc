#include "extensions/filters/common/rbac/engine_impl.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace RBAC {

RoleBasedAccessControlEngineImpl::RoleBasedAccessControlEngineImpl(
    const envoy::config::filter::http::rbac::v2::RBAC& config, bool disabled)
    : engine_disabled_(disabled), config_(config) {
  if (disabled) {
    return;
  }

  for (const auto& policy : config.rules().policies()) {
    policies_.emplace_back(policy.second);
  }

  for (const auto& policy : config.permissive_rules().policies()) {
    permissive_policies_.emplace_back(policy.second);
  }
}

RoleBasedAccessControlEngineImpl::RoleBasedAccessControlEngineImpl(
    const envoy::config::filter::http::rbac::v2::RBACPerRoute& per_route_config)
    : RoleBasedAccessControlEngineImpl(per_route_config.rbac(), per_route_config.disabled()) {}

bool RoleBasedAccessControlEngineImpl::allowed(const Network::Connection& connection,
                                               const Envoy::Http::HeaderMap& headers,
                                               EnforcementMode mode) const {
  if (engine_disabled_) {
    return true;
  }

  // No enforced rule is set indicates RBAC isn't enabled for enforcement mode.
  if ((mode == EnforcementMode::ENFORCED) && !config_.has_rules()) {
    return true;
  }

  // No permissive rule is set indicates RBAC isn't enabled for permissive mode.
  if ((mode == EnforcementMode::PERMISSIVE) && !config_.has_permissive_rules()) {
    return true;
  }

  const std::vector<PolicyMatcher>& policies =
      mode == EnforcementMode::PERMISSIVE ? permissive_policies_ : policies_;

  bool allowed_if_matched = mode == EnforcementMode::PERMISSIVE
                                ? config_.permissive_rules().action() ==
                                      envoy::config::rbac::v2alpha::RBAC_Action::RBAC_Action_ALLOW
                                : config_.rules().action() ==
                                      envoy::config::rbac::v2alpha::RBAC_Action::RBAC_Action_ALLOW;

  bool matched = false;
  for (const auto& policy : policies) {
    if (policy.matches(connection, headers)) {
      matched = true;
      break;
    }
  }

  // only allowed if:
  //   - matched and ALLOW action
  //   - not matched and DENY action
  return matched == allowed_if_matched;
}

} // namespace RBAC
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy

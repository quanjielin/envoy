#pragma once

#include "envoy/config/filter/http/rbac/v2/rbac.pb.h"

#include "extensions/filters/common/rbac/engine.h"
#include "extensions/filters/common/rbac/matchers.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace RBAC {

class RoleBasedAccessControlEngineImpl : public RoleBasedAccessControlEngine {
public:
  RoleBasedAccessControlEngineImpl(const envoy::config::filter::http::rbac::v2::RBAC& config);

  RoleBasedAccessControlEngineImpl(
      const envoy::config::filter::http::rbac::v2::RBACPerRoute& per_route_config);

  bool allowed(const Network::Connection& connection, const Envoy::Http::HeaderMap& headers,
               EnforcementMode mode) const override;

private:
  // RBAC Configuration.
  const envoy::config::filter::http::rbac::v2::RBAC config_;

  std::vector<PolicyMatcher> policies_;

  std::vector<PolicyMatcher> permissive_policies_;
};

} // namespace RBAC
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy

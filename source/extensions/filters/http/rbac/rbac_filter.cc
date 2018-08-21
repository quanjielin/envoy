#include "extensions/filters/http/rbac/rbac_filter.h"

#include "envoy/stats/scope.h"

#include "common/http/utility.h"

#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RBACFilter {

static const std::string resp_code_200 = "200";
static const std::string resp_code_403 = "403";
static const std::string shadow_policy_id_field = "shadow_effective_policyID";
static const std::string shadow_resp_code_field = "shadow_response_code";

RoleBasedAccessControlFilterConfig::RoleBasedAccessControlFilterConfig(
    const envoy::config::filter::http::rbac::v2::RBAC& proto_config,
    const std::string& stats_prefix, Stats::Scope& scope)
    : stats_(Filters::Common::RBAC::generateStats(stats_prefix, scope)),
      engine_(Filters::Common::RBAC::createEngine(proto_config)),
      shadow_engine_(Filters::Common::RBAC::createShadowEngine(proto_config)) {}

const absl::optional<Filters::Common::RBAC::RoleBasedAccessControlEngineImpl>&
RoleBasedAccessControlFilterConfig::engine(const Router::RouteConstSharedPtr route,
                                           Filters::Common::RBAC::EnforcementMode mode) const {
  if (!route || !route->routeEntry()) {
    return engine(mode);
  }

  const std::string& name = HttpFilterNames::get().Rbac;
  const auto* entry = route->routeEntry();
  const auto* route_local =
      entry->perFilterConfigTyped<RoleBasedAccessControlRouteSpecificFilterConfig>(name)
          ?: entry->virtualHost()
                 .perFilterConfigTyped<RoleBasedAccessControlRouteSpecificFilterConfig>(name);

  if (route_local) {
    return route_local->engine(mode);
  }

  return engine(mode);
}

RoleBasedAccessControlRouteSpecificFilterConfig::RoleBasedAccessControlRouteSpecificFilterConfig(
    const envoy::config::filter::http::rbac::v2::RBACPerRoute& per_route_config)
    : engine_(Filters::Common::RBAC::createEngine(per_route_config.rbac())),
      shadow_engine_(Filters::Common::RBAC::createShadowEngine(per_route_config.rbac())) {}

Http::FilterHeadersStatus RoleBasedAccessControlFilter::decodeHeaders(Http::HeaderMap& headers,
                                                                      bool) {
  ENVOY_LOG(
      debug,
      "checking request: remoteAddress: {}, localAddress: {}, ssl: {}, headers: {}, "
      "dynamicMetadata: {}",
      callbacks_->connection()->remoteAddress()->asString(),
      callbacks_->connection()->localAddress()->asString(),
      callbacks_->connection()->ssl()
          ? "uriSanPeerCertificate: " + callbacks_->connection()->ssl()->uriSanPeerCertificate() +
                ", subjectPeerCertificate: " +
                callbacks_->connection()->ssl()->subjectPeerCertificate()
          : "none",
      headers, callbacks_->requestInfo().dynamicMetadata().DebugString());

  std::string effective_policy_id;
  const auto& shadow_engine =
      config_->engine(callbacks_->route(), Filters::Common::RBAC::EnforcementMode::Shadow);

  if (shadow_engine.has_value()) {
    std::string shadow_resp_code = resp_code_200;
    if (shadow_engine->allowed(*callbacks_->connection(), headers,
                               callbacks_->requestInfo().dynamicMetadata(), &effective_policy_id)) {
      ENVOY_LOG(debug, "shadow allowed");
      config_->stats().shadow_allowed_.inc();
    } else {
      ENVOY_LOG(debug, "shadow denied");
      config_->stats().shadow_denied_.inc();
      shadow_resp_code = resp_code_403;
    }


    const auto& filter_metadata = callbacks_->requestInfo().dynamicMetadata().filter_metadata();
    //auto filter_metadata = callbacks_->requestInfo().dynamicMetadata().mutable_filter_metadata();
    const auto filter_it = filter_metadata.find(HttpFilterNames::get().Rbac);
    if (filter_it != filter_metadata.end()) {
      std::cout << "***Found dynamic_metadata found for filter for rbac";
      ProtobufWkt::Struct metrics;

      if (!effective_policy_id.empty()) {
        ProtobufWkt::Value policy_id;
        policy_id.set_string_value(effective_policy_id);
        (*metrics.mutable_fields())[shadow_policy_id_field] = policy_id;
        //std::cout << "***policy_id " << policy_id.string_value() << "\n";
      }

      ProtobufWkt::Value resp_code;
      resp_code.set_string_value(shadow_resp_code);
      (*metrics.mutable_fields())[shadow_resp_code_field] = resp_code;
      //std::cout << "***shadow_resp_code " << resp_code.string_value() << "\n";


      //auto filter_meta = filter_metadata.at(HttpFilterNames::get().Rbac);
      //filter_meta.MergeFrom(metrics);
      callbacks_->requestInfo().setDynamicMetadata(HttpFilterNames::get().Rbac, metrics);

      /*
      std::cout << "*****metrics length " << metrics.fields().size() << "\n";
      std::cout << "*****metrics content " << metrics.DebugString() << "\n"; */

      std::cout << "*****metadata debug string*****" << callbacks_->requestInfo().dynamicMetadata().filter_metadata().at(HttpFilterNames::get().Rbac).DebugString() << "\n";

      
      std::cout << "*****fileds length " << callbacks_->requestInfo().dynamicMetadata().filter_metadata().at(HttpFilterNames::get().Rbac).fields().size();
      
      
      auto fm = callbacks_->requestInfo().dynamicMetadata().filter_metadata();
      auto fields = fm[HttpFilterNames::get().Rbac].fields();
      for (auto it = fields.begin(); it != fields.end(); it++) {
        std::cout << "-----first " << it->first << "\n";
        std::cout << "-----second " << it->second.string_value() << "\n";
      } 
    } else {
      ENVOY_LOG(debug, "No dynamic_metadata found for filter {}",
                Extensions::HttpFilters::HttpFilterNames::get().Rbac);
      std::cout << "***No dynamic_metadata found for filter for rbac";
    }
  }

  const auto& engine =
      config_->engine(callbacks_->route(), Filters::Common::RBAC::EnforcementMode::Enforced);
  if (engine.has_value()) {
    if (engine->allowed(*callbacks_->connection(), headers,
                        callbacks_->requestInfo().dynamicMetadata(), nullptr)) {
      ENVOY_LOG(debug, "enforced allowed");
      config_->stats().allowed_.inc();
      return Http::FilterHeadersStatus::Continue;
    } else {
      ENVOY_LOG(debug, "enforced denied");
      callbacks_->sendLocalReply(Http::Code::Forbidden, "RBAC: access denied", nullptr);
      config_->stats().denied_.inc();
      return Http::FilterHeadersStatus::StopIteration;
    }
  }

  ENVOY_LOG(debug, "no engine, allowed by default");
  return Http::FilterHeadersStatus::Continue;
}

} // namespace RBACFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

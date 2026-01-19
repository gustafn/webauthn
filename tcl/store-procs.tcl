# SPDX-License-Identifier: MPL-2.0

::xo::library doc {
    Storage object for temporary storing authentication data
}

nx::Class create ::xo::WebAuthnStore::Cache {
    #
    # Cache for "ceremony" state (challenge, origin, rpId, return_url)
    #
    set :cacheName webauth
    ns_cache_create ${:cacheName} 10000
    :public object method set {{-expires 5m} key dict} {
        ns_cache_eval -expires $expires -- ${:cacheName} $key {set dict} 
    }
    :public object method get {key} {
        ns_cache_get ${:cacheName} $key
    }
    :public object method unset {key} {
        ns_cache_flush ${:cacheName} $key
    }
    :public object method keys {} {
        ns_cache_keys ${:cacheName}
    }
}

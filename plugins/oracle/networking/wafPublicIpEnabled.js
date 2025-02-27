var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'WAF Public IP Enabled',
    category: 'Networking',
    description: 'Determine if Public IPs have WAF enabled',
    more_info: 'Every Public IP address should have a firewall enabled to control access to the endpoints. Enabling a Web Application Firewall follows security best practices and helps prevent malicious attempts to access the network.',
    recommended_action: '1. Enter the WAF Policies service under Security. 2. Create a new WAF Policy with the unprotected public IP address.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/WAF/Concepts/gettingstarted.htm',
    apis: ['publicIp:list', 'waasPolicy:list', 'waasPolicy:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var allIps = [];
        async.each(regions.publicIp, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var publicIps = helpers.addSource(cache, source,
                    ['publicIp', 'list', region]);

                if (!publicIps) return rcb();

                if (publicIps.err || !publicIps.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Public IPs: ' + helpers.addError(publicIps), region);
                    return rcb();
                }

                if (!publicIps.data.length) {
                    helpers.addResult(results, 0, 'No Public IPs present', region);
                    return rcb();
                };
                
                publicIps.data.forEach(publicIp => {
                    allIps.push(publicIp.ipAddress);
                });
            };

            rcb();
        }, function(){
            async.each(regions.waasPolicy, function(region, lcb) {
                var waasPolicies = helpers.addSource(cache, source,
                    ['waasPolicy', 'get', region]);

                if (!waasPolicies) return lcb();

                if ((waasPolicies.err && waasPolicies.err.length) || !waasPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for waas Policies: ' + helpers.addError(waasPolicies), region);
                    return lcb();
                }

                if (!waasPolicies.data.length) {
                    helpers.addResult(results, 0, 'No waas Policies present', region);
                    return lcb();
                }
                waasPolicies.data.forEach(waasPolicy => {
                    for (var x in waasPolicy.origins) {
                        var origin = waasPolicy.origins[x];
                        if (allIps.indexOf(origin.uri) > -1) {
                            allIps.splice(allIps.indexOf(origin.uri),1);
                        };
                    };
                });

                lcb();
            }, function(){
                if (allIps.length) {
                    helpers.addResult(results, 2,
                        'The following Public IPs do not have WAF enabled: ' + allIps.join(', '));
                } else {
                    helpers.addResult(results, 2,
                        'All Public IPs have WAF enabled');
                };
                callback(null, results, source);
            });
            
        }, function(){
            callback(null, results, source);
        });
    }
};
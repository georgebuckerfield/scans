var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Default SSM Policy In Use',
    category: 'IAM',
    description: 'Detect usage of the default AmazonEC2RoleforSSM policy.',
    more_info: 'This policy grants a large number of IAM permissions. In general, more specific IAM policies should be used.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/auth-and-access-control-iam-identity-based-access-control.html#managed-policies',
    recommended_action: 'Replace the policy with more specific managed policies for SSM.',
    apis: ['IAM:listPolicies'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listPolicies = helpers.addSource(cache, source,
                ['iam', 'listPolicies', region]);

        if (!listPolicies) {
          console.log('Unable to list policies')
          return callback(null, results, source);
        }

        if (listPolicies.err || !listPolicies.data) {
            helpers.addResult(results, 3,
                'Unable to query for policies: ' + helpers.addError(listPolicies));
            return callback(null, results, source);
        }

        if (!listPolicies.data.length) {
            helpers.addResult(results, 0, 'No policies found');
            return callback(null, results, source);
        }

        async.each(listPolicies.data, function(policy, cb){
            if (!policy.PolicyName) return cb();

            if (policy.PolicyName=='AmazonEC2RoleforSSM') {
                if (policy.AttachmentCount > 0) {
                  helpers.addResult(results, 1, 'Policy: ' + policy.PolicyName + ' is attached to ' + policy.AttatchmentCount + ' IAM principal(s).', 'global', policy.Arn);
                }
                else if (policy.AttachmentCount==0) {
                  helpers.addResult(results, 0, 'Policy: ' + policy.PolicyName + ' is not attached to any IAM principals.', 'global', policy.Arn);
                }
            }
            return cb()
        }, function(){
            callback(null, results, source);
        });
    }
};

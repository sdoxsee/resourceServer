'use strict';

angular.module('resourceserverApp')
    .factory('Register', function ($resource) {
        return $resource('api/register', {}, {
        });
    });



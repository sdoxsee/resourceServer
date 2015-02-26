'use strict';

angular.module('resourceserverApp')
    .controller('LogoutController', function (Auth) {
        Auth.logout();
    });

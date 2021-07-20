using System;
using Microsoft.AspNetCore.Mvc;
using Nop.Core;
using Nop.Core.Caching;
using Nop.Plugin.ExternalAuth.NovellActiveDirectory.Models;
using Nop.Plugin.ExternalAuth.NovellActiveDirectory.Services;
using Nop.Services.Authentication;
using Nop.Services.Authentication.External;
using Nop.Services.Configuration;
using Nop.Services.Customers;
using Nop.Services.Events;
using Nop.Services.Localization;
using Nop.Services.Logging;
using Nop.Services.Messages;
using Nop.Services.Orders;
using Nop.Services.Security;
using Nop.Services.Stores;
using Nop.Web.Framework.Controllers;
using Nop.Web.Framework.Mvc.Filters;

namespace Nop.Plugin.ExternalAuth.NovellActiveDirectory.Controllers
{
    public class NovellActiveDirectoryAuthenticationController : BasePluginController
    {
        private readonly IAuthenticationPluginManager _authenticationPluginManager;

        private readonly IAuthenticationService _authenticationService;

        private readonly IStaticCacheManager _cacheManager;

        private readonly ICustomerActivityService _customerActivityService;

        private readonly ICustomerService _customerService;

        private readonly IEventPublisher _eventPublisher;

        private readonly IExternalAuthenticationService _externalAuthenticationService;

        private readonly ILdapService _ldapService;

        private readonly ILocalizationService _localizationService;

        private readonly INotificationService _notificationService;
        private readonly NovellActiveDirectoryExternalAuthSettings _novellActiveDirectoryExternalAuthSettings;

        private readonly IPermissionService _permissionService;

        private readonly ISettingService _settingService;

        private readonly IShoppingCartService _shoppingCartService;

        private readonly IStoreContext _storeContext;

        private readonly IStoreService _storeService;

        private readonly IWorkContext _workContext;

        public NovellActiveDirectoryAuthenticationController(
            NovellActiveDirectoryExternalAuthSettings novellActiveDirectoryExternalAuthSettings,
            IExternalAuthenticationService externalAuthenticationService, ILocalizationService localizationService,
            IPermissionService permissionService, ISettingService settingService, ICustomerService customerService,
            IAuthenticationService authenticationService, IShoppingCartService shoppingCartService,
            IWorkContext workContext, IEventPublisher eventPublisher, ICustomerActivityService customerActivityService,
            IStaticCacheManager cacheManager, INotificationService notificationService, ILdapService ldapService,
            IStoreService storeService, IStoreContext storeContext,
            IAuthenticationPluginManager authenticationPluginManager)
        {
            _novellActiveDirectoryExternalAuthSettings = novellActiveDirectoryExternalAuthSettings;
            _externalAuthenticationService = externalAuthenticationService;
            _localizationService = localizationService;
            _permissionService = permissionService;
            _settingService = settingService;
            _customerService = customerService;
            _authenticationService = authenticationService;
            _shoppingCartService = shoppingCartService;
            _workContext = workContext;
            _eventPublisher = eventPublisher;
            _customerActivityService = customerActivityService;
            _cacheManager = cacheManager;
            _notificationService = notificationService;
            _ldapService = ldapService;
            _storeService = storeService;
            _storeContext = storeContext;
            _authenticationPluginManager = authenticationPluginManager;
        }

        [AuthorizeAdmin()]
        [Area("Admin")]
        public IActionResult Configure()
        {
            if (!_permissionService.Authorize(StandardPermissionProvider.ManageExternalAuthenticationMethods))
                return AccessDeniedView();
            var activeStoreScopeConfiguration = _storeContext.ActiveStoreScopeConfiguration;
            var novellActiveDirectorySettings =
                _settingService.LoadSetting<NovellActiveDirectoryExternalAuthSettings>(activeStoreScopeConfiguration);

            var configurationNovellModel = new ConfigurationNovellModel
            {
                LdapPath = novellActiveDirectorySettings.LdapPath,
                LdapUsername = novellActiveDirectorySettings.LdapUsername,
                LdapPassword = novellActiveDirectorySettings.LdapPassword,
                UseInstantLogin = novellActiveDirectorySettings.UseInstantLogin,
                SearchBase = novellActiveDirectorySettings.SearchBase,
                ContainerName = novellActiveDirectorySettings.ContainerName,
                Domain = novellActiveDirectorySettings.Domain,
                DomainDistinguishedName = novellActiveDirectorySettings.DomainDistinguishedName,
                LdapServerPort = novellActiveDirectorySettings.LdapServerPort,
                UseSSL = novellActiveDirectorySettings.UseSSL
            };

            return View("~/Plugins/ExternalAuth.NovellActiveDirectory/Views/Configure.cshtml",
                configurationNovellModel);
        }

        [HttpPost]
        [AuthorizeAdmin()]
        [Area("Admin")]
        public IActionResult Configure(ConfigurationNovellModel novellModel)
        {
            if (!_permissionService.Authorize(StandardPermissionProvider.ManageExternalAuthenticationMethods))
                return AccessDeniedView();
            if (!ModelState.IsValid) return Configure();
            var activeStoreScopeConfiguration = _storeContext.ActiveStoreScopeConfiguration;

            _novellActiveDirectoryExternalAuthSettings.LdapPath = novellModel.LdapPath;
            _novellActiveDirectoryExternalAuthSettings.LdapUsername = novellModel.LdapUsername;
            _novellActiveDirectoryExternalAuthSettings.LdapPassword = novellModel.LdapPassword;
            _novellActiveDirectoryExternalAuthSettings.UseInstantLogin = novellModel.UseInstantLogin;
            _novellActiveDirectoryExternalAuthSettings.SearchBase = novellModel.SearchBase;
            _novellActiveDirectoryExternalAuthSettings.ContainerName = novellModel.ContainerName;
            _novellActiveDirectoryExternalAuthSettings.Domain = novellModel.Domain;
            _novellActiveDirectoryExternalAuthSettings.DomainDistinguishedName = novellModel.DomainDistinguishedName;
            _novellActiveDirectoryExternalAuthSettings.LdapServerPort = novellModel.LdapServerPort;
            _novellActiveDirectoryExternalAuthSettings.UseSSL = novellModel.UseSSL;
            var num = _storeService.GetAllStores().Count > 1 ? activeStoreScopeConfiguration : 0;
            _settingService.SaveSetting(_novellActiveDirectoryExternalAuthSettings, num);
            _settingService.ClearCache();
            //_cacheManager.Clear();
            _customerActivityService.InsertActivity("EditNovellActiveDirectoryExternalAuthSettings",
                "Edit Novell Active Directory External Auth Settings");
            _notificationService.SuccessNotification(_localizationService.GetResource("Admin.Plugins.Saved"));

            return Configure();
        }

        public IActionResult SignIn(SignInViewModel model, string returnUrl)
        {
            // bool flag = !this._externalAuthenticationService.ExternalAuthenticationMethodIsAvailable("ExternalAuth.NovellActiveDirectory");
            var flag = _authenticationPluginManager
                .IsPluginActive("ExternalAuth.NovellActiveDirectory", _workContext.CurrentCustomer,
                    _storeContext.CurrentStore.Id);

            if (!flag) throw new NopException("Novell Active Directory authentication module cannot be loaded");
            var flag2 = string.IsNullOrEmpty(_novellActiveDirectoryExternalAuthSettings.LdapPath);
            if (flag2) throw new NopException("Novell Active Directory authentication module not configured");
            IActionResult result2;
            if (string.IsNullOrEmpty(model.AdUserName))
            {
                ExternalAuthorizerHelper.AddErrorsToDisplay(
                    _localizationService.GetResource(
                        "Plugins.ExternalAuth.NovellActiveDirectory.WindowsUserNotAvailable"));
                result2 = new RedirectToActionResult("Login", "Customer",
                    !string.IsNullOrEmpty(returnUrl) ? new {ReturnUrl = returnUrl} : null);
            }
            else
            {
                var email = string.Empty;
                LdapUser ldapUser = null;
                try
                {
                    ldapUser = _ldapService.GetUserByUserName(model.AdUserName);
                    if (null == ldapUser)
                    {
                        ExternalAuthorizerHelper.AddErrorsToDisplay(
                            _localizationService.GetResource(
                                "Plugins.ExternalAuth.NovellActiveDirectory.UserNotFound"));
                        return new RedirectToActionResult("Login", "Customer",
                            !string.IsNullOrEmpty(returnUrl) ? new {ReturnUrl = returnUrl} : null);
                    }
                }
                catch (Exception e)
                {
                    ExternalAuthorizerHelper.AddErrorsToDisplay(
                        _localizationService.GetResource("Plugins.ExternalAuth.NovellActiveDirectory.LdapError : " +
                                                         e));
                    return new RedirectToActionResult("Login", "Customer",
                        !string.IsNullOrEmpty(returnUrl) ? new {ReturnUrl = returnUrl} : null);
                }

                try
                {
                    var flag6 = _ldapService.Authenticate(ldapUser.DistinguishedName, model.AdPassword);
                    if (flag6)
                    {
                        var authenticationParameters = new ExternalAuthenticationParameters
                        {
                            ProviderSystemName = "ExternalAuth.NovellActiveDirectory",
                            AccessToken = Guid.NewGuid().ToString(),
                            Email = ldapUser.Email,
                            ExternalIdentifier = ldapUser.Email,
                            ExternalDisplayIdentifier = ldapUser.Email
                        };
                        return _externalAuthenticationService.Authenticate(authenticationParameters, returnUrl);
                    }
                }
                catch (Exception e)
                {
                    ExternalAuthorizerHelper.AddErrorsToDisplay(
                        _localizationService.GetResource("Plugins.ExternalAuth.NovellActiveDirectory.LdapError : " +
                                                         "auth " + e));
                    return new RedirectToActionResult("Login", "Customer",
                        !string.IsNullOrEmpty(returnUrl) ? new {ReturnUrl = returnUrl} : null);
                }
            }


            ExternalAuthorizerHelper.AddErrorsToDisplay(
                _localizationService.GetResource("Plugins.ExternalAuth.NovellActiveDirectory.LdapError"));
            result2 = new RedirectToActionResult("Login", "Customer",
                !string.IsNullOrEmpty(returnUrl) ? new {ReturnUrl = returnUrl} : null);
            return result2;
        }
    }
}
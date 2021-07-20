using Microsoft.AspNetCore.Mvc;
using Nop.Core;
using Nop.Core.Http.Extensions;
using Nop.Services.Customers;
using Nop.Web.Framework.Components;

namespace Nop.Plugin.ExternalAuth.NovellActiveDirectory.Components
{
    [ViewComponent(Name = "WidgetsActiveDirectoryAuthentication")]
    public class WidgetsActiveDirectoryViewComponent : NopViewComponent
    {
        private readonly ICustomerService _customerService;
        private readonly NovellActiveDirectoryExternalAuthSettings _novellActiveDirectoryExternalAuthSettings;
        private readonly IWorkContext _workContext;

        public WidgetsActiveDirectoryViewComponent(IWorkContext workContext,
            ICustomerService customerService,
            NovellActiveDirectoryExternalAuthSettings novellActiveDirectoryExternalAuthSettings)
        {
            _workContext = workContext;
            _customerService = customerService;
            _novellActiveDirectoryExternalAuthSettings = novellActiveDirectoryExternalAuthSettings;
        }

        public IViewComponentResult Invoke()
        {
            var flag = _novellActiveDirectoryExternalAuthSettings.UseInstantLogin &&
                       !_customerService.IsRegistered(_workContext.CurrentCustomer) &&
                       !HttpContext.Session.Get<bool>("NovellLogout");

            return View("~/Plugins/ExternalAuth.NovellActiveDirectory/Views/WidgetPublicInfo.cshtml", flag);
        }
    }
}
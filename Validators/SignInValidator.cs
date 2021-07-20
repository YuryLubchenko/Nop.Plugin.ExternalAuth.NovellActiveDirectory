using FluentValidation;
using Nop.Plugin.ExternalAuth.NovellActiveDirectory.Models;
using Nop.Services.Localization;
using Nop.Web.Framework.Validators;

namespace Nop.Plugin.ExternalAuth.NovellActiveDirectory.Validators
{
    public class SignInValidator : BaseNopValidator<SignInViewModel>
    {
        public SignInValidator(ILocalizationService localizationService)
        {
            //login by ad password
            RuleFor(x => x.AdPassword).NotEmpty()
                .WithMessage(
                    localizationService.GetResource(
                        "Plugins.ExternalAuth.NovellActiveDirectory.LdapPassword.Required"));
        }
    }
}
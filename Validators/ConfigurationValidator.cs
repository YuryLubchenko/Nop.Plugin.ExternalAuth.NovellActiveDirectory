using FluentValidation;
using Nop.Plugin.ExternalAuth.NovellActiveDirectory.Models;
using Nop.Services.Localization;
using Nop.Web.Framework.Validators;

namespace Nop.Plugin.ExternalAuth.NovellActiveDirectory.Validators
{
    public class ConfigurationValidator : BaseNopValidator<ConfigurationNovellModel>
    {
        public ConfigurationValidator(ILocalizationService localizationService)
        {
            RuleFor(x => x.LdapPath).NotEmpty()
                .WithMessage(
                    localizationService.GetResource(
                        "Plugins.ExternalAuth.NovellActiveDirectory.fields.LdapPath.Required"));
        }
    }
}
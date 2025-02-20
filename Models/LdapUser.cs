﻿using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace Nop.Plugin.ExternalAuth.NovellActiveDirectory.Models
{
    // Add profile data for application users by adding properties to the LdapUser class
    public class LdapUser : IdentityUser, ILdapEntry
    {
        [NotMapped]
        [Display(Name = "Password")]
        [Required(ErrorMessage = "You must enter your password!")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [NotMapped] public string SamAccountName { get; set; }

        [NotMapped] public string[] MemberOf { get; set; }

        [NotMapped] public bool IsDomainAdmin { get; set; }

        [NotMapped] public bool MustChangePasswordOnNextLogon { get; set; }

        [NotMapped] public string UserPrincipalName { get; set; }

        [NotMapped] public string DisplayName { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "You must enter your first name!")]
        public string FirstName { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "You must enter your last name!")]
        public string LastName { get; set; }

        [NotMapped] public string FullName => $"{FirstName} {LastName}";

        [NotMapped]
        [Required(ErrorMessage = "You must enter your email address!")]
        [EmailAddress(ErrorMessage = "You must enter a valid email address.")]
        public string EmailAddress { get; set; }

        [NotMapped] public string Description { get; set; }

        [NotMapped] public string Phone { get; set; }

        [NotMapped] public LdapAddress Address { get; set; }

        public override string SecurityStamp => Guid.NewGuid().ToString("D");

        public override string UserName
        {
            get => Name;
            set => Name = value;
        }

        public override string NormalizedUserName => UserName;

        public override string NormalizedEmail => EmailAddress;

        public override string Id => Guid.NewGuid().ToString("D");

        public override string Email => EmailAddress;

        [NotMapped] public string ObjectSid { get; set; }

        [NotMapped] public string ObjectGuid { get; set; }

        [NotMapped] public string ObjectCategory { get; set; }

        [NotMapped] public string ObjectClass { get; set; }


        [NotMapped] public string Name { get; set; }

        [NotMapped] public string CommonName { get; set; }

        [NotMapped] public string DistinguishedName { get; set; }

        [NotMapped] public int SamAccountType { get; set; }
    }

    public class LdapAddress
    {
        public string Street { get; set; }
        public string PostalCode { get; set; }
        public string City { get; set; }
        public string StateName { get; set; }
        public string CountryName { get; set; }
        public string CountryCode { get; set; }
    }
}
﻿using System.Collections.Generic;
using Nop.Plugin.ExternalAuth.NovellActiveDirectory.Models;

namespace Nop.Plugin.ExternalAuth.NovellActiveDirectory.Services
{
    public interface ILdapService
    {
        ICollection<LdapEntry> GetGroups(string groupName, bool getChildGroups = false);

        ICollection<LdapUser> GetUsersInGroup(string groupName);

        ICollection<LdapUser> GetUsersInGroups(ICollection<LdapEntry> groups = null);

        ICollection<LdapUser> GetUsersByEmailAddress(string emailAddress);

        ICollection<LdapUser> GetAllUsers();

        LdapUser GetAdministrator();

        LdapUser GetUserByUserName(string userName);

        void AddUser(LdapUser user, string password);

        void DeleteUser(string distinguishedName);

        bool Authenticate(string distinguishedName, string password);
    }
}
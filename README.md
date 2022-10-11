# TrusTree (WIP)

> This project is a work in progress and should not be used in production

## Executive Summary

Access Control is essential for any modern application. Yet, poorly implemented, it can lead to privilege escalation attacks which can violate traditional rules.

TrusTrees are a new type of access control system that can be used to enforce access control rules in a way that is both secure and flexible.

Rather than traditional rules, which give a binary "yes or no," it allows permissions based on how a user navigates a system.

This offers multiple benefits:
- User navigation can be tracked and used to determine permissions
- Irregular behavior, such as querying data from an incorrect form or API (common in SQL injection), can be easily identified
- In the event of access token compromise, the scope of attack can be significantly minimized.

## Technical Cornerstones
### Chain of Trust

As a user navigates through an application, two things happen:
- A cryptographic chain of trust is established
- Scope is protected and reduced

The chain of trust leads to a smaller attack surface and greater auditability should an access token be compromised or abuse of permissions occur.

### Scope
Each access token in the chain of trust has a scope. This scope is the set of permissions that the token is allowed to use.

When a user navigates to a new page, the scope is reduced to the intersection of the current scope and the new page's scope.

This means that, should a vulnerability be found in application code or an API, the scope of that vulnerability is limited. For example, a SQL injection attack on a page about salaries could not query user authentication information, even if the account has access to both tables.
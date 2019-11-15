# OAuth 1.0a utility functions for .NET Core

Even though the OAuth 1.0a specification has been officially made obsolete by [OAuth 2.0](https://tools.ietf.org/html/rfc6749), it remains in active use for legacy implementations. A recent project required me to be able to consume an OAuth 1.0a request, specifically to calculate and validate the `oauth_signature` parameter. This was in a .NET Core 3.0 project, which (as far as I can tell!) doesn't have any libraries that help with this specification. 

I really didn't feel comfortable taking a dependency hit on this one by bringing in a third-party NuGet package. Many of the options provided far more than I needed, and most were (understandably) no longer in active development or supported. Taking on an unsupported "black box" dependency with anything related to security doesn't sit quite right with me.

So I rolled my own implementation for just the subset of features that I needed to support (verification only, and OAuth parameters passed as form post data). This is not meant to be a complete implementation, but can serve as a starting point for anyone else who finds themselves in a similar situation and isn't interested in bringing in a dependency.

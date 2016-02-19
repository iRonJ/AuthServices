using System;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.Linq;
using System.Net;
using System.Configuration;

using System.Security.Claims;
using Kentor.AuthServices.Configuration;
using Kentor.AuthServices.Saml2P;
using System.Xml;

namespace Kentor.AuthServices.WebSso
{
    internal class SingleSignoutCommand : ICommand
    {
        public CommandResult Run(HttpRequestData request, IOptions options)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            var binding = Saml2Binding.Get(request);


            if (binding != null)
            {
                string unpackedPayload = null;
                try
                {
                    unpackedPayload = binding.Unbind(request);
                   
                    var samlResponse = Saml2Response.Read(unpackedPayload);
                   
                    return ProcessResponse(options, samlResponse);
                }
                catch (FormatException ex)
                {
                    throw new BadFormatSamlResponseException(
                            "The SAML Response did not contain valid BASE64 encoded data.", ex);
                }
                catch (XmlException ex)
                {
                    var newEx = new BadFormatSamlResponseException(
                        "The SAML response contains incorrect XML", ex);

                    // Add the payload to the exception
                    newEx.Data["Saml2Response"] = unpackedPayload;
                    throw newEx;
                }
                catch (Exception ex)
                {
                    // Add the payload to the existing exception
                    ex.Data["Saml2Response"] = unpackedPayload;
                    throw;
                }
            }

            return CreateResult(
                new EntityId(request.QueryString["idp"].FirstOrDefault()),
                request.QueryString["ReturnUrl"].FirstOrDefault(),
                request,
                options);
        }

        public static CommandResult CreateResult(
            EntityId idpEntityId,
            string returnPath,
            HttpRequestData request,
            IOptions options,
            object relayData = null)
        {
            var urls = new AuthServicesUrls(request, options.SPOptions);

            

            IdentityProvider idp;
            if (idpEntityId == null || idpEntityId.Id == null)
            {
                if (options.SPOptions.DiscoveryServiceUrl != null)
                {
                    return RedirectToDiscoveryService(returnPath, options.SPOptions, urls);
                }

                idp = options.IdentityProviders.Default;
            }
            else
            {
                if (!options.IdentityProviders.TryGetValue(idpEntityId, out idp))
                {
                    throw new InvalidOperationException("Unknown idp");
                }
            }

            Uri returnUrl = options.SPOptions.ReturnUrl;
            if (!Uri.TryCreate(options.SPOptions.ReturnUrl.ToString(),UriKind.RelativeOrAbsolute,out returnUrl)) {
              
            }
            //if (!string.IsNullOrEmpty(returnPath))
            //{
            //    Uri.TryCreate(request.Url, returnPath, out returnUrl);
            //}

            string nameIdentifierValue = string.Empty;
            string nameIdentifierFormat = string.Empty;
            if (request.NameIdentifier != null)
            {
                nameIdentifierValue = request.NameIdentifier.Value;
                nameIdentifierFormat = request.NameIdentifier.Properties[ClaimProperties.SamlNameIdentifierFormat];
            }

            var signoutRequest = idp.CreateSignOutRequest(returnUrl, nameIdentifierValue, nameIdentifierFormat, relayData);

            return idp.Bind(signoutRequest);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "returnUrl")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "SpOptions")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "ReturnUrl")]
        private static CommandResult ProcessResponse(IOptions options, Saml2Response samlResponse)
        {
             // var principal = new ClaimsPrincipal(samlResponse.GetClaims(options));

           // var principal = new ClaimsPrincipal();

            
            var requestState = samlResponse.GetRequestState(options);

            if (requestState == null && options.SPOptions.ReturnUrl == null)
            {
                throw new ConfigurationErrorsException(MissingReturnUrlMessage);
            }

            //System.IdentityModel.Services.WSFederationAuthenticationModule.FederatedSignOut(samlResponse.DestinationUrl, options.SPOptions.ReturnUrl);


            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = options.SPOptions.ReturnUrl
            };
        }

        internal const string MissingReturnUrlMessage =
@"Unsolicited SAML response received, but no ReturnUrl is configured.

When receiving unsolicited SAML responses (i.e. IDP initiated login),
AuthServices will redirect the client to the configured ReturnUrl after
successful authentication, but it is not configured.

In code-based config, add a ReturnUrl by setting the
options.SpOptions.ReturnUrl property. In the config file, set the returnUrl
attribute of the <kentor.authServices> element.";

        private static CommandResult RedirectToDiscoveryService(
            string returnPath,
            ISPOptions spOptions,
            AuthServicesUrls authServicesUrls)
        {
            string returnUrl = authServicesUrls.SignInUrl.OriginalString;

            if (!string.IsNullOrEmpty(returnPath))
            {
                returnUrl += "?ReturnUrl=" + Uri.EscapeDataString(returnPath);
            }

            var redirectLocation = string.Format(
                CultureInfo.InvariantCulture,
                "{0}?entityID={1}&return={2}&returnIDParam=idp",
                spOptions.DiscoveryServiceUrl,
                Uri.EscapeDataString(spOptions.EntityId.Id),
                Uri.EscapeDataString(returnUrl));

            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = new Uri(redirectLocation)
            };
        }
    }
}
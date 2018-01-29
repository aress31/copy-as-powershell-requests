/*
 * Copyright 2018 Alexandre Teyar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package copy_as_powershell_requests.utils;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

public class ExtensionHelper {

  private IBurpExtenderCallbacks burpExtenderCallbacks;
  private boolean hasBody;
  private boolean hasContentType;
  private boolean hasCookieParams;
  private boolean hasURIParams;
  private boolean hasUserAgent;
  private boolean isBase64;
  private boolean isStandard;

  public ExtensionHelper(IBurpExtenderCallbacks burpExtenderCallbacks) {
    this.burpExtenderCallbacks = burpExtenderCallbacks;
  }

  public StringBuilder buildPowershellRequest(
      IHttpRequestResponse selectedMessage, boolean isBase64) {
    IRequestInfo requestInfo = this.burpExtenderCallbacks.getHelpers()
        .analyzeRequest(selectedMessage);
    StringBuilder stringBuilder = new StringBuilder();
    String method = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
        .escape(requestInfo.getMethod()).toString();
    String URI = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
        .escape(requestInfo.getUrl().toString()).toString();

    if (!(StaticData.SUPPORTED_METHODS.contains(method))) {
      this.burpExtenderCallbacks.issueAlert(
          "The \"" + StringUtils.abbreviate(method, 16)
              + "\" method is not supported by PowerShell Invoke-WebRequest.");
    }

    stringBuilder.append("$method = [Microsoft.PowerShell.Commands.WebRequestMethod]::")
        .append("\"").append(method).append("\"")
        .append(System.lineSeparator()).append("$URI = [System.Uri]::new(\"").append(URI)
        .append("\")")
        .append(System.lineSeparator()).append("$maximumRedirection = [System.Int32] ")
        .append(StaticData.IWR_MAXIMUM_REDIRECTION)
        .append(System.lineSeparator());
    stringBuilder.append(processHeaders(requestInfo.getHeaders()));
    stringBuilder.append(processParams(requestInfo.getParameters()));
    stringBuilder.append(processBody(selectedMessage, requestInfo, isBase64));
    stringBuilder.append("$response = (").append(StaticData.IWR_BASIC_INVOCATION);

    if (this.hasContentType) {
      stringBuilder.append("-ContentType $contentType ");
    }

    if (this.hasUserAgent) {
      stringBuilder.append("-UserAgent $userAgent ");
    }

    if (this.hasCookieParams) {
      stringBuilder.append("-WebSession $webSession ");
    }

    if (this.hasBody && this.isBase64) {
      if (!(stringBuilder.toString().contains("-Body"))) {
        stringBuilder.append("-Body $bytes ");
      } else {
        stringBuilder.deleteCharAt(stringBuilder.lastIndexOf(" ")).append(", $bytes ");
      }
    } else if (this.hasBody && this.isStandard) {
      if (!(stringBuilder.toString().contains("-Body"))) {
        stringBuilder.append("-Body $body ");
      } else {
        stringBuilder.deleteCharAt(stringBuilder.lastIndexOf(" ")).append(", $body ");
      }
    }

    if (this.hasURIParams) {
      if (!(stringBuilder.toString().contains("-Body"))) {
        stringBuilder.append("-Body $URIParams ");
      } else {
        stringBuilder.deleteCharAt(stringBuilder.lastIndexOf(" ")).append(", $URIParams ");
      }
    }

    stringBuilder.deleteCharAt(stringBuilder.lastIndexOf(" ")).append(")")
        .append(System.lineSeparator()).append("$response");
    
    return stringBuilder;
  }

  private StringBuilder processHeaders(List<String> headers) {
    this.hasContentType = false;
    this.hasUserAgent = false;
    StringBuilder stringBuilder = new StringBuilder(
        "$headers = [System.Collections.Generic.Dictionary[string,string]]::new()")
        .append(System.lineSeparator());

    // skip the first header line
    for (String header : headers.subList(1, headers.size())) {
      String headerName = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
          .escape((header.split(": ")[0] + "")).toString();
      String headerValue = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
          .escape((header.split(": ")[1] + "")).toString();

      if (!(StaticData.SKIP_HEADERS.contains(headerName.toLowerCase()))) {
        switch (header.split(": ")[0].toLowerCase()) {
          case "content-type":
            this.hasContentType = true;
            stringBuilder.append("$contentType = [System.String]::new(\"").append(headerValue)
                .append("\")")
                .append(System.lineSeparator());
            break;
          case "user-agent":
            this.hasUserAgent = true;
            stringBuilder.append("$userAgent = [System.String]::new(\"").append(headerValue)
                .append("\")")
                .append(System.lineSeparator());
            break;
          default:
            stringBuilder.append("$headers.Add(\"").append(headerName).append("\", \"")
                .append(headerValue).append("\")")
                .append(System.lineSeparator());
            break;
        }
      }
    }

    return stringBuilder;
  }

  private StringBuilder processParams(List<IParameter> parameters) {
    this.hasCookieParams = false;
    this.hasURIParams = false;
    boolean isCookieFirstIteration = true;
    boolean isURLFirstIteration = true;
    StringBuilder stringBuilder = new StringBuilder();

    if (!(parameters.isEmpty())) {
      for (IParameter parameter : parameters) {
        String parameterName = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
            .escape(parameter.getName()).toString();
        String parameterValue = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
            .escape(parameter.getValue()).toString();

        switch (parameter.getType()) {
          case IParameter.PARAM_URL:
            if (isURLFirstIteration) {
              this.hasURIParams = true;
              stringBuilder.append(
                  "$URIParams = [System.Collections.Generic.Dictionary[string,string]]::new()")
                  .append(System.lineSeparator());
              isURLFirstIteration = false;
            }

            stringBuilder.append("$URIParams.Add(\"").append(parameterName).append("\", \"")
                .append(parameterValue).append("\")")
                .append(System.lineSeparator());
            break;
          case IParameter.PARAM_COOKIE:
            if (isCookieFirstIteration) {
              this.hasCookieParams = true;
              stringBuilder.append(
                  "$webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()")
                  .append(System.lineSeparator());
              isCookieFirstIteration = false;
            }

            stringBuilder.append("$webSession.Cookies.Add($URI, [System.Net.Cookie]::new(\"")
                .append(parameterName).append("\", \"").append(parameterValue).append("\"))")
                .append(System.lineSeparator());
            break;
          default:
            break;
        }
      }
    }

    return stringBuilder;
  }

  private StringBuilder processBody(IHttpRequestResponse selectedMessage,
      IRequestInfo requestInfo, boolean isBase64) {
    this.hasBody = false;
    this.isBase64 = false;
    this.isStandard = false;
    int bodyOffset = requestInfo.getBodyOffset();
    byte[] request = selectedMessage.getRequest();
    StringBuilder stringBuilder = new StringBuilder();

    if (request.length > bodyOffset) {
      this.hasBody = true;

      if (isBase64) {
        this.isBase64 = true;
        String postData = Base64.getEncoder()
            .encodeToString(Arrays.copyOfRange(request, bodyOffset, request.length));
        stringBuilder.append("$body64 = [System.String]::new(\"").append(postData)
            .append("\")")
            .append(System.lineSeparator()).append(
            "$bytes = [System.Convert]::FromBase64String($body64)")
            .append(System.lineSeparator());
      } else {
        this.isStandard = true;
        String postData = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL).escape(
            this.burpExtenderCallbacks.getHelpers()
                .bytesToString(Arrays.copyOfRange(request, bodyOffset, request.length))).toString();
        stringBuilder.append("$body = [System.String]::new(\"").append(postData).append("\")")
            .append(System.lineSeparator());
      }
    }

    return stringBuilder;
  }
}

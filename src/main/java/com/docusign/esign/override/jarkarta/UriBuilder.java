package com.docusign.esign.override.jarkarta;

import java.net.URISyntaxException;
import org.apache.http.client.utils.URIBuilder;

/** @author jrnazareth */
public class UriBuilder extends URIBuilder {

  public UriBuilder(String string) throws URISyntaxException {
    super(string);
  }

  public UriBuilder path(String path) {
    setPath(path);
    return this;
  }

  public UriBuilder scheme(String scheme) {
    setScheme(scheme);
    return this;
  }

  public UriBuilder queryParam(String param, String value) {
    addParameter(param, value);
    return this;
  }

  public static UriBuilder fromUri(String root) throws URISyntaxException {
    return new UriBuilder(root);
  }
}

package org.apache.geronimo.microprofile.impl.jwtauth.jwt;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

@ApplicationScoped
@Path("public-keys")
public class PublicKeyResource {

    @Inject
    private KidMapper kidMapper;

    @GET
    @Path("{kid}")
    @Produces()
    public String getPublicKey(@PathParam("kid") String kid) {
        return kidMapper.loadKey(kid);
    }
}
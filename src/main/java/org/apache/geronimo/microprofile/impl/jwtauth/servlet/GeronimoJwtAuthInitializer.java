/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.geronimo.microprofile.impl.jwtauth.servlet;

import static java.util.Optional.ofNullable;

import java.util.Comparator;
import java.util.EnumSet;
import java.util.Set;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import javax.servlet.annotation.HandlesTypes;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.eclipse.microprofile.auth.LoginConfig;

@HandlesTypes(LoginConfig.class)
public class GeronimoJwtAuthInitializer implements ServletContainerInitializer {
    @Override
    public void onStartup(final Set<Class<?>> classes, final ServletContext ctx) {
        final GeronimoJwtAuthConfig config = GeronimoJwtAuthConfig.create();
        final boolean forceSetup = "true".equalsIgnoreCase(config.read("filter.active", "false"));
        if (forceSetup) {
            doSetup(ctx, config, null);
            return;
        }
        ofNullable(classes).filter(c -> !c.isEmpty())
                .flatMap(marked -> marked.stream()
                    .filter(Application.class::isAssignableFrom) // needed? what's the issue dropping it? nothing normally
                    .filter(app -> app.isAnnotationPresent(LoginConfig.class) &&
                            "MP-JWT".equalsIgnoreCase(app.getAnnotation(LoginConfig.class).authMethod()))
                    .min(Comparator.comparing(Class::getName)))  // to be deterministic
                .ifPresent(app -> doSetup(ctx, config, app));
    }

    private void doSetup(final ServletContext ctx, final GeronimoJwtAuthConfig config, final Class<?> app) {
        final FilterRegistration.Dynamic filter = ctx.addFilter("geronimo-microprofile-jwt-auth-filter", GeronimoJwtAuthFilter.class);
        filter.setAsyncSupported(true);
        final String[] mappings = ofNullable(app).map(a -> a.getAnnotation(ApplicationPath.class))
                .map(ApplicationPath::value)
                .map(v -> (!v.startsWith("/") ? "/" : "") +
                        (v.contains("{") ? v.substring(0, v.indexOf("{")) : v) +
                        (v.endsWith("/") ? "" : "/") +
                        "*")
                .map(v -> new String[]{v})
                .orElseGet(() -> {
                    final ServletRegistration defaultServlet = ctx.getServletRegistration(Application.class.getName());
                    if (defaultServlet != null && !defaultServlet.getMappings().isEmpty()) {
                        return defaultServlet.getMappings().toArray(new String[defaultServlet.getMappings().size()]);
                    }

                    final String[] servletMapping = ctx.getServletRegistrations().values().stream()
                            .filter(r -> r.getInitParameter("javax.ws.rs.Application") != null)
                            .flatMap(r -> r.getMappings().stream())
                            .toArray(String[]::new);
                    if (servletMapping.length > 0) {
                        return servletMapping;
                    }

                    // unlikely
                    return new String[]{config.read("filter.mapping.default", "/*")};
                });
        filter.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), false, mappings);
    }
}

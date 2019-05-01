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
package org.apache.geronimo.microprofile.impl.jwtauth.jaxrs;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Stream;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

// not done at cdi level since a lot of apps already activate it
// so we would break apps too easily
// todo: probably make it configurable
@Provider
@Dependent
public class RolesAllowedFeature implements DynamicFeature {
    @Inject
    private GroupMapper mapper;

    @Override
    public void configure(final ResourceInfo resourceInfo, final FeatureContext featureContext) {
        final Map<Class<?>, Annotation> methodAnnotations = collectConfig(resourceInfo.getResourceMethod());
        if (methodAnnotations.size() > 1) {
            throw new IllegalArgumentException("Ambiguous configuration for " + resourceInfo.getResourceMethod() + ": " + methodAnnotations);
        }

        final Map<Class<?>, Annotation> classAnnotations = collectConfig(unwrapClazz(resourceInfo.getResourceClass()));
        if (classAnnotations.size() > 1) {
            throw new IllegalArgumentException("Ambiguous configuration for " + resourceInfo.getResourceClass() + ": " + classAnnotations);
        }

        if (classAnnotations.isEmpty() && methodAnnotations.isEmpty()) {
            return;
        }

        try {
            ofNullable(RolesAllowedFeature.class.getClassLoader())
                    .orElseGet(ClassLoader::getSystemClassLoader)
                    .loadClass("javax.annotation.security.PermitAll");
        } catch (final ClassNotFoundException cnfe) {
            return;
        }

        final boolean denyAll = methodAnnotations.containsKey(DenyAll.class) || (methodAnnotations.isEmpty() && classAnnotations.containsKey(DenyAll.class));
        final boolean permitAll = !denyAll && (methodAnnotations.containsKey(PermitAll.class) || (methodAnnotations.isEmpty() && classAnnotations.containsKey(PermitAll.class)));
        final Collection<String> roles = denyAll || permitAll ?
                emptyList() :
                Stream.of(RolesAllowed.class.cast(ofNullable(methodAnnotations.get(RolesAllowed.class)).orElseGet(() -> classAnnotations.get(RolesAllowed.class))).value())
                        .flatMap(it -> mapper.map(it).stream())
                        .collect(toSet());
        featureContext.register(new RolesAllowedRequestFilter(denyAll, permitAll, roles));
    }

    private Map<Class<?>, Annotation> collectConfig(final AnnotatedElement annotatedElement) {
        return Stream.of(DenyAll.class, PermitAll.class, RolesAllowed.class)
                .filter(annotatedElement::isAnnotationPresent)
                .map(annotatedElement::getAnnotation)
                .collect(toMap(Annotation::annotationType, identity()));
    }

    private AnnotatedElement unwrapClazz(final Class<?> resourceClass) {
        Class<?> current = resourceClass;
        while (current.getName().contains("$$") && current.getSuperclass() != null) {
            current = current.getSuperclass();
        }
        return current;
    }
}

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
package org.apache.geronimo.microprofile.impl.jwtauth.cdi;

import static java.util.Objects.requireNonNull;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static java.util.Optional.ofNullable;
import static java.util.function.Function.identity;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collector;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.Default;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Vetoed;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AfterDeploymentValidation;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.enterprise.util.AnnotationLiteral;
import javax.enterprise.util.Nonbinding;
import javax.inject.Provider;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.spi.JsonProvider;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.apache.geronimo.microprofile.impl.jwtauth.jwt.ContextualJsonWebToken;
import org.apache.geronimo.microprofile.impl.jwtauth.servlet.TokenAccessor;
import org.apache.geronimo.microprofile.impl.jwtauth.servlet.JwtRequest;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

public class GeronimoJwtAuthExtension implements Extension {
    private final ThreadLocal<TokenAccessor> request = new ThreadLocal<>();

    private final Collection<Injection> injectionPoints = new HashSet<>(8);
    private final Collection<Throwable> errors = new ArrayList<>();
    private JsonProvider json;

    void setClaimMethodsBinding(@Observes final BeforeBeanDiscovery beforeBeanDiscovery) {
        beforeBeanDiscovery.configureQualifier(Claim.class)
                .methods().forEach(m -> m.remove(it -> it.annotationType() == Nonbinding.class));
        json = JsonProvider.provider();
    }

    void captureInjections(@Observes final ProcessInjectionPoint<?, ?> processInjectionPoint) {
        final InjectionPoint injectionPoint = processInjectionPoint.getInjectionPoint();
        ofNullable(injectionPoint.getAnnotated().getAnnotation(Claim.class))
                .flatMap(claim -> createInjection(claim, injectionPoint.getType()))
                .ifPresent(injectionPoints::add);
    }

    void addClaimBeans(@Observes final AfterBeanDiscovery afterBeanDiscovery) {
        // it is another instance than th eone used in our initializer but it should be backed by the same impl
        afterBeanDiscovery.addBean()
                .id(GeronimoJwtAuthExtension.class.getName() + "#" + GeronimoJwtAuthConfig.class.getName())
                .beanClass(GeronimoJwtAuthConfig.class)
                .types(GeronimoJwtAuthConfig.class, Object.class)
                .qualifiers(Default.Literal.INSTANCE, Any.Literal.INSTANCE)
                .scope(ApplicationScoped.class)
                .createWith(ctx -> GeronimoJwtAuthConfig.create());

        afterBeanDiscovery.addBean()
                .id(GeronimoJwtAuthExtension.class.getName() + "#" + JsonWebToken.class.getName())
                .beanClass(JsonWebToken.class)
                .types(JsonWebToken.class, Object.class)
                .qualifiers(Default.Literal.INSTANCE, Any.Literal.INSTANCE)
                .scope(ApplicationScoped.class)
                .createWith(ctx -> new ContextualJsonWebToken(() -> {
                    final TokenAccessor request = this.request.get();
                    if (request == null) {
                        throw new IllegalStateException("No JWT in this request");
                    }
                    return request.getToken();
                }));

        injectionPoints.forEach(injection ->
                afterBeanDiscovery.addBean()
                        .id(GeronimoJwtAuthExtension.class.getName() + "#" + injection.getId())
                        .beanClass(injection.findClass())
                        .qualifiers(injection.literal(), Any.Literal.INSTANCE)
                        .scope(injection.findScope())
                        .types(injection.type, Object.class)
                        .createWith(ctx -> injection.createInstance(request.get())));

        injectionPoints.clear();
    }

    void afterDeployment(@Observes final AfterDeploymentValidation afterDeploymentValidation) {
        errors.forEach(afterDeploymentValidation::addDeploymentProblem);
    }

    private Optional<Injection> createInjection(final Claim claim, final Type type) {
        if (ParameterizedType.class.isInstance(type)) {
            final ParameterizedType pt = ParameterizedType.class.cast(type);
            if (pt.getActualTypeArguments().length == 1) {
                final Type raw = pt.getRawType();
                final Type arg = pt.getActualTypeArguments()[0];

                if (raw == Provider.class || raw == Instance.class) {
                    return createInjection(claim, arg);
                }
                if (raw == Optional.class) {
                    return createInjection(claim, arg)
                            .map(it -> new Injection(claim.value(), claim.standard(), type) {
                                @Override
                                Object createInstance(final TokenAccessor jwtRequest) {
                                    return ofNullable(it.createInstance(jwtRequest));
                                }
                            });
                }
                if (raw == ClaimValue.class) {
                    final String name = getClaimName(claim);
                    return createInjection(claim, arg)
                            .map(it -> new Injection(claim.value(), claim.standard(), type) {
                                @Override
                                Object createInstance(final TokenAccessor jwtRequest) {
                                    return new ClaimValue<Object>() {
                                        @Override
                                        public String getName() {
                                            return name;
                                        }

                                        @Override
                                        public Object getValue() {
                                            return it.createInstance(jwtRequest);
                                        }
                                    };
                                }
                            });
                }
                if (Class.class.isInstance(raw) && Collection.class.isAssignableFrom(Class.class.cast(raw))) {
                    return of(new Injection(claim.value(), claim.standard(), type));
                }
            }
        } else if (Class.class.isInstance(type)) {
            final Class<?> clazz = Class.class.cast(type);
            if (JsonValue.class.isAssignableFrom(clazz)) {
                if (JsonString.class.isAssignableFrom(clazz)) {
                    return of(new Injection(claim.value(), claim.standard(), clazz) {
                        @Override
                        Object createInstance(final TokenAccessor jwtRequest) {
                            final Object instance = super.createInstance(jwtRequest);
                            if (JsonString.class.isInstance(instance)) {
                                return instance;
                            }
                            return json.createValue(String.class.cast(instance));
                        }
                    });
                }
                if (JsonNumber.class.isAssignableFrom(clazz)) {
                    return of(new Injection(claim.value(), claim.standard(), clazz) {
                        @Override
                        Object createInstance(final TokenAccessor jwtRequest) {
                            final Object instance = super.createInstance(jwtRequest);
                            if (JsonNumber.class.isInstance(instance)) {
                                return instance;
                            }
                            return json.createValue(Number.class.cast(instance).doubleValue());
                        }
                    });
                }
                if (JsonObject.class.isAssignableFrom(clazz)) {
                    return of(new Injection(claim.value(), claim.standard(), clazz));
                }
                if (JsonArray.class.isAssignableFrom(clazz)) {
                    return of(new Injection(claim.value(), claim.standard(), clazz) {
                        @Override
                        Object createInstance(final TokenAccessor jwtRequest) {
                            final Object instance = super.createInstance(jwtRequest);
                            if (instance == null) {
                                return null;
                            }
                            if (JsonArray.class.isInstance(instance)) {
                                return instance;
                            }
                            if (Set.class.isInstance(instance)) {
                                return ((Set<String>) instance).stream()
                                        .collect(Collector.of(
                                                json::createArrayBuilder,
                                                JsonArrayBuilder::add,
                                                JsonArrayBuilder::addAll,
                                                JsonArrayBuilder::build));
                            }
                            throw new IllegalArgumentException("Unsupported value: " + instance);
                        }
                    });
                }
            } else {
                final Class<?> objectType = wrapPrimitives(clazz);
                if (CharSequence.class.isAssignableFrom(clazz) || Double.class.isAssignableFrom(objectType) ||
                        Long.class.isAssignableFrom(objectType) || Integer.class.isAssignableFrom(objectType)) {
                    return of(new Injection(claim.value(), claim.standard(), objectType));
                }
            }
        }
        errors.add(new IllegalArgumentException(type + " not supported by JWT-Auth implementation"));
        return empty();
    }

    private Class<?> wrapPrimitives(final Class<?> type) {
        if (long.class == type) {
            return Long.class;
        }
        if (int.class == type) {
            return Integer.class;
        }
        if (double.class == type) {
            return Double.class;
        }
        return type;
    }

    private static String getClaimName(final Claim claim) {
        return getClaimName(claim.value(), claim.standard());
    }

    private static String getClaimName(final String name, final Claims val) {
        return of(name).filter(s -> !s.isEmpty()).orElse(val.name());
    }

    public void execute(final HttpServletRequest req, final ServletRunnable task) {
        try {
            final TokenAccessor jwtRequest = requireNonNull(JwtRequest.class.isInstance(req) ?
                            JwtRequest.class.cast(req) : JwtRequest.class.cast(req.getAttribute(JwtRequest.class.getName())),
                    "No JwtRequest");
            execute(jwtRequest, task);
        } catch (final IOException | ServletException e) {
            throw new IllegalStateException(e);
        }
    }

    public void execute(final TokenAccessor req, final ServletRunnable task) throws ServletException, IOException {
        request.set(req); // we want to track it ourself to support propagation properly when needed
        try {
            task.run();
        } finally {
            request.remove();
        }
    }

    @FunctionalInterface
    public interface ServletRunnable {
        void run() throws ServletException, IOException;
    }

    private static class Injection {
        private final String name;
        private final Claims claims;
        private final Type type;
        private final int hash;
        private final Function<Object, Object> transformer;
        private final String runtimeName;

        private Injection(final String name, final Claims claims, final Type type) {
            this.name = name;
            this.claims = claims;
            this.type = type;

            Function<Object, Object> transformer;
            try {
                Claims.valueOf(getClaimName(name, claims));
                transformer = identity();
            } catch (final IllegalArgumentException iae) {
                if (type == String.class) {
                    transformer = val -> val == null ? null : JsonString.class.cast(val).getString();
                } else if (type == Long.class) {
                    transformer = val -> val == null ? null : JsonNumber.class.cast(val).longValue();
                } else {
                    transformer = identity();
                }
            }
            this.transformer = transformer;
            this.runtimeName = getClaimName(name, claims);

            {
                int result = name.hashCode();
                result = 31 * result + claims.hashCode();
                hash = 31 * result + type.hashCode();
            }
        }

        private String getId() {
            return name + "/" + claims + "/" + type;
        }

        private Class<?> findClass() {
            if (Class.class.isInstance(type)) {
                return Class.class.cast(type);
            }
            if (ParameterizedType.class.isInstance(type)) {
                ParameterizedType current = ParameterizedType.class.cast(type);
                while (!Class.class.isInstance(current.getRawType())) {
                    current = ParameterizedType.class.cast(current.getRawType());
                }
                return Class.class.cast(current.getRawType());
            }
            throw new IllegalArgumentException("Can't find a class from " + type);
        }

        private Class<? extends Annotation> findScope() {
            if (ClaimValue.class == findClass()) {
                return RequestScoped.class;
            }
            return Dependent.class;
        }

        private Annotation literal() {
            return new ClaimLiteral(name, claims);
        }

        Object createInstance(final TokenAccessor jwtRequest) {
            return transformer.apply(jwtRequest.getToken().getClaim(runtimeName));
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final Injection injection = Injection.class.cast(o);
            return runtimeName.equals(injection.runtimeName) && type.equals(injection.type);
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public String toString() {
            return "Injection{claim='" + runtimeName + "', type=" + type + '}';
        }
    }

    @Vetoed
    private static class ClaimLiteral extends AnnotationLiteral<Claim> implements Claim {
        private final String name;
        private final Claims claims;

        private ClaimLiteral(final String name, final Claims claims) {
            this.name = name;
            this.claims = claims;
        }

        @Override
        public String value() {
            return name;
        }

        @Override
        public Claims standard() {
            return claims;
        }
    }
}

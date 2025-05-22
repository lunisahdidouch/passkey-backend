package com.sogeti.passkey_backend_yubico;



import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import org.springframework.stereotype.Repository;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.yubico.webauthn.data.PublicKeyCredentialType.PUBLIC_KEY;

@Repository
public class InMemoryCredentialRepository implements CredentialRepository {
    private final SecureRandom random = new SecureRandom();

     final Map<String, UserIdentity> users = new ConcurrentHashMap<>();
     private final Map<ByteArray, Set<RegisteredCredential>> credentialsByUserHandle = new ConcurrentHashMap<>();
     private final Map<ByteArray, String> credentialIdToUsername = new ConcurrentHashMap<>();



    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        Optional<ByteArray> userHandleOpt = getUserHandleForUsername(username);
        if (userHandleOpt.isPresent()) {
            ByteArray userHandle = userHandleOpt.get();
            Set<RegisteredCredential> credentials = credentialsByUserHandle.get(userHandle);
            if (credentials != null) {
                return credentials.stream()
                        .map(credential -> PublicKeyCredentialDescriptor.builder()
                                .id(credential.getCredentialId())
                                .type(PUBLIC_KEY)
                                .build())
                        .collect(Collectors.toSet());
            }
        }
        return Collections.emptySet();
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        //        Map<String, ByteArray> filteredUsersMap = new ConcurrentHashMap<>();
//                .Stream()
//                .filter(map -> map.getKey().getName().equals(username))
//                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        for(Map.Entry<String, UserIdentity> userHandle : users.entrySet()){
            if(userHandle.getKey().equals(username)){
                UserIdentity userIdentity = userHandle.getValue();
                return Optional.of(userIdentity.getId());
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        for(Map.Entry<String, UserIdentity> entry : users.entrySet()){
            UserIdentity userIdentity = entry.getValue();
            if(userIdentity.getId().equals(userHandle)){
                return Optional.of(userIdentity.getName());
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Set<RegisteredCredential> credentials = credentialsByUserHandle.get(userHandle);
        if (credentials != null) {
            return credentials.stream()
                    .filter(credential -> credential.getCredentialId().equals(credentialId))
                    .findFirst();
        }
        return Optional.empty();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return credentialsByUserHandle.values().stream()
                .flatMap(Set::stream)
                .filter(credential -> credential.getCredentialId().equals(credentialId))
                .collect(Collectors.toSet());

    }


    public UserIdentity createUser(String username, String displayName, ByteArray userHandle) {
        UserIdentity userIdentity = UserIdentity.builder()
                        .name(username)
                        .displayName(displayName)
                        .id(userHandle)
                        .build();
        users.put(username, userIdentity);
        credentialsByUserHandle.put(userHandle, ConcurrentHashMap.newKeySet());
        return userIdentity;
    }

    public void addCredential(UserIdentity user, RegisteredCredential credential) {
        credentialsByUserHandle.computeIfAbsent(user.getId(), k -> ConcurrentHashMap.newKeySet()).add(credential);
        credentialIdToUsername.put(credential.getCredentialId(), user.getName());
    }

    public void updateSignatureCount(ByteArray userHandle, ByteArray credentialId, long newSignatureCount) {
        Set<RegisteredCredential> credentials = credentialsByUserHandle.get(userHandle);
        if (credentials != null) {
            RegisteredCredential credentialToUpdate = null;
            for (RegisteredCredential credential : credentials) {
                if (credential.getCredentialId().equals(credentialId)) {
                    credentialToUpdate = credential;
                    break;
                }
            }

            if (credentialToUpdate != null) {
                RegisteredCredential updatedCredential = RegisteredCredential.builder()
                        .credentialId(credentialToUpdate.getCredentialId())
                        .userHandle(credentialToUpdate.getUserHandle())
                        .publicKeyCose(credentialToUpdate.getPublicKeyCose())
                        .signatureCount(newSignatureCount)
                        .build();
                credentials.remove(credentialToUpdate);
                credentials.add(updatedCredential);
            }
        }
    }

    private ByteArray generateRandom(int length) {
         byte[] bytes = new byte[length];
         random.nextBytes(bytes);
         return new ByteArray(bytes);
    }

}

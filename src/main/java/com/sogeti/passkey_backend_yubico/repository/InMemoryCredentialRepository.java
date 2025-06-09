package com.sogeti.passkey_backend_yubico.repository;


import com.sogeti.passkey_backend_yubico.model.PasskeyInfo;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static com.yubico.webauthn.data.PublicKeyCredentialType.PUBLIC_KEY;

@Repository
public class InMemoryCredentialRepository implements CredentialRepository {

     final Map<String, UserIdentity> users = new ConcurrentHashMap<>();
     private final Map<ByteArray, Set<RegisteredCredential>> credentialsByUserHandle = new ConcurrentHashMap<>();
     private final Map<ByteArray, String> credentialIdToUsername = new ConcurrentHashMap<>();

    private final Map<String, PasskeyInfo> passkeyMetadata = new ConcurrentHashMap<>();
    private final Map<String, Integer> userPasskeyCounters = new ConcurrentHashMap<>();

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
        Optional<Map.Entry<String, UserIdentity>> userIdentity = users.entrySet().stream()
        .filter(map -> map.getKey().equals(username))
        .findFirst();

        if (userIdentity.isPresent()) {
            UserIdentity id = userIdentity.get().getValue();
            return Optional.of(id.getId());
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

    public Optional<UserIdentity> getUserByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public boolean userExists(String username) {
        return users.containsKey(username);
    }
    
    public UserIdentity createUser(String username, String displayName, ByteArray userHandle) {
        UserIdentity userIdentity = UserIdentity.builder()
                        .name(username)
                        .displayName(displayName)
                        .id(userHandle)
                        .build();
        users.put(username, userIdentity);
        credentialsByUserHandle.put(userHandle, ConcurrentHashMap.newKeySet());
        userPasskeyCounters.put(username, 0);
        return userIdentity;
    }

    public void addCredential(UserIdentity user, RegisteredCredential credential) {
        credentialsByUserHandle.computeIfAbsent(user.getId(), k -> ConcurrentHashMap.newKeySet()).add(credential);
        credentialIdToUsername.put(credential.getCredentialId(), user.getName());

        String username = user.getName();
        int counter = userPasskeyCounters.getOrDefault(username, 0) + 1;
        userPasskeyCounters.put(username, counter);

        String credentialIdStr = credential.getCredentialId().getBase64Url();
        PasskeyInfo passkeyInfo = new PasskeyInfo(
                credentialIdStr,
                "Passkey " + counter,
                LocalDateTime.now(),
                LocalDateTime.now()
        );
        passkeyMetadata.put(credentialIdStr, passkeyInfo);
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
    public List<PasskeyInfo> getPasskeysForUser(String username) {
        Optional<ByteArray> userHandleOpt = getUserHandleForUsername(username);
        if (userHandleOpt.isPresent()) {
            Set<RegisteredCredential> credentials = credentialsByUserHandle.get(userHandleOpt.get());
            if (credentials != null) {
                return credentials.stream()
                        .map(credential -> passkeyMetadata.get(credential.getCredentialId().getBase64Url()))
                        .filter(Objects::nonNull)
                        .collect(Collectors.toList());
            }
        }
        return Collections.emptyList();
    }

    public boolean updatePasskeyName(String username, String passkeyId, String newName) {
        PasskeyInfo info = passkeyMetadata.get(passkeyId);
        if (info != null) {
            // Verify the passkey belongs to the user
            Optional<ByteArray> userHandleOpt = getUserHandleForUsername(username);
            if (userHandleOpt.isPresent()) {
                Set<RegisteredCredential> credentials = credentialsByUserHandle.get(userHandleOpt.get());
                if (credentials != null && credentials.stream().anyMatch(cred -> cred.getCredentialId().getBase64Url().equals(passkeyId))) {
                    info.setName(newName);
                    return true;
                }
            }
        }
        return false;
    }

    public boolean deletePasskey(String username, String passkeyId) {
        Optional<ByteArray> userHandleOpt = getUserHandleForUsername(username);
        if (userHandleOpt.isPresent()) {
            Set<RegisteredCredential> credentials = credentialsByUserHandle.get(userHandleOpt.get());
            if (credentials != null) {
                boolean removed = credentials.removeIf(cred -> cred.getCredentialId().getBase64Url().equals(passkeyId));
                if (removed) {
                    passkeyMetadata.remove(passkeyId);
                    // Find and remove the credential ID mapping
                    credentialIdToUsername.entrySet().removeIf(entry -> entry.getKey().getBase64Url().equals(passkeyId));
                    return true;
                }
            }
        }
        return false;
    }

    public int getPasskeyCountForUser(String username) {
        List<PasskeyInfo> passkeys = getPasskeysForUser(username);
        return passkeys.size();
    }


}

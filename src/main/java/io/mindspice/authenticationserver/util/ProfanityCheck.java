package io.mindspice.authenticationserver.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;
import java.util.stream.Collectors;


public class ProfanityCheck {
    private final Set<String> wordList;

    public ProfanityCheck(String wordFile) {
        this.wordList = loadWordList(wordFile);
    }

    public boolean profanityCheck(String word) {
        for (var badWord : wordList) {
            if (word.contains(badWord)) { return true; }
        }
        return false;
    }

    private Set<String> loadWordList(String fileName) {
        try {
            return Files.lines(Paths.get(fileName))
                    .map(String::toLowerCase) // Convert to lower case
                    .collect(Collectors.toSet());
        } catch (IOException e) {
            throw new RuntimeException("Error reading word list file", e);
        }
    }
}

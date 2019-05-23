package com.mjasinski.lab.encryption;

import com.mjasinski.java.lab.solver.impl.BruteForceSolver;
import com.mjasinski.java.lab.utils.Item;
import com.mjasinski.java.lab.utils.ProblemInstance;
import com.mjasinski.java.lab.utils.Solution;
import com.mjasinski.lab.encryption.keygen.KeyGen;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

/**
 * Created by Marcin on 13.05.2019
 */
@SuppressWarnings("Duplicates")
public class Main {

    private static final int minRange = 1;
    private static final int maxRange = 1000;

    public static void main(String[] args) {

        String userOperation;
        Scanner scanner = new Scanner(System.in);

        while (true) {

            printMenu();
            userOperation = scanner.nextLine();

            switch (userOperation) {

                case "1":
                    generateKeys();
                    break;

                case "2":
                    encryptFile();
                    break;

                case "3":
                    decryptFile();
                    break;

                case "4":
                    solveKnapsackProblem();
                    break;

                default:
                    System.out.println("Invalid operation.");
                    break;
            }
        }
    }

    public static void printMenu() {

        System.out.print("\n=== JAVA ENCRYPTION === "
                + "\n1) Generate new public/private key pair with RSA Algorithm"
                + "\n2) Encrypt file"
                + "\n3) Decrypt file"
                + "\n4) Use encrypted JAR to solve Knapsack Problem"
        );

        System.out.print("\n > ");
    }

    public static void generateKeys(){

        try {
            KeyGen keyGen = new KeyGen(1024);
            keyGen.createKeys();

            keyGen.writeToFile("KeyPair/publicKey", keyGen.getPublicKey().getEncoded());
            keyGen.writeToFile("KeyPair/privateKey", keyGen.getPrivateKey().getEncoded());

            System.out.println("Public/private key pair generated and saved under \"KeyPair/publicKey\" nad \"KeyPair/privateKey\"");

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void encryptFile() {

        Scanner scanner = new Scanner(System.in);
        System.out.println("Type file name to encrypt (file must exist in \"TestData\" directory:");
        String fileName = scanner.nextLine();

        try {
            // Reading data from file
            File file = new File("TestData/" + fileName);
            FileInputStream fis = new FileInputStream(file);
            byte[] fileBytes = new byte[(int) file.length()];
            fis.read(fileBytes);
            fis.close();

            // Setting up crypto module
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] keyBytes = Files.readAllBytes(new File("KeyPair/privateKey").toPath());
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            // encryption
            byte[] encryptedFile = cipher.doFinal(fileBytes);

            String encryptedFilePath = "TestData/encrypted_" + fileName;
            FileOutputStream fos = new FileOutputStream(encryptedFilePath);
            fos.write(encryptedFile);
            fos.flush();
            fos.close();

            System.out.println("Encryption successful, file location: " + encryptedFilePath);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    private static void decryptFile() {

        Scanner scanner = new Scanner(System.in);
        System.out.println("Type file name to decrypt (file must exist in \"TestData\" directory:");
        String fileName = scanner.nextLine();

        try{
            // Reading data from file
            File file = new File("TestData/" + fileName);
            FileInputStream fis = new FileInputStream(file);
            byte[] fileBytes = new byte[(int) file.length()];
            fis.read(fileBytes);
            fis.close();

            // Setting up crypto module
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] keyBytes = Files.readAllBytes(new File("KeyPair/publicKey").toPath());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(spec);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            // decryption
            byte[] decryptedFile = cipher.doFinal(fileBytes);

            fileName = fileName.replace("encrypted_", "");
            String decryptedFilePath = "TestData/decrypted_" + fileName;
            FileOutputStream fos = new FileOutputStream(decryptedFilePath);
            fos.write(decryptedFile);
            fos.flush();
            fos.close();

            System.out.println("Decryption successful, file location: " + decryptedFilePath);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    private static void solveKnapsackProblem(){

        System.out.println("Verifying JAR file signature...");

        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("cmd.exe", "/c", "cd D:\\Dokumenty\\Projekty\\Java\\Java_encryption && jarsigner -verify -verbose -certs Java_lab1.jar");

        try {

            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }

            int exitVal = process.waitFor();

            String commandOutput = output.toString();
            if (exitVal == 0) {
                System.out.println("Finished verifying JAR signature.");

                if(commandOutput.contains("jar verified") && commandOutput.contains("Signed by \"CN=Martin, OU=PWR, O=PWR, L=Wroclaw, ST=Poland, C=PL\"")){
                    System.out.println("JAR signature verified.");
                } else {
                    System.out.println("Invalid JAR signature.");
                    return;
                }
            } else {
                System.out.println("Error verifying JAR signature.");
                return;
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        long seed = generateRandomIntIntRange(minRange, maxRange);
        ProblemInstance problemInstance = getRandomInstance(seed);
        System.out.println("\nProblem instance: ");
        System.out.println("Number of items: " + problemInstance.getItemList().size());
        System.out.println("Summary knapsack capacity: " + problemInstance.getCapacity());

        BruteForceSolver bruteForceSolver = new BruteForceSolver();
        Solution solution = bruteForceSolver.solve(problemInstance);

        System.out.println("Problem solved using Brute-force approach:");
        System.out.println(solution.toString());
    }

    private static ProblemInstance getRandomInstance(long seed) {

        long problemSize = seed / 2;
        int capacity = (int) seed * 2 + 5;

        List<Item> items = new ArrayList<>();
        for (int i = 1; i <= problemSize; i++) {
            items.add(new Item(i + 5, (i * 1.5 + seed) % seed));
        }

        return new ProblemInstance(capacity, items);
    }

    private static long generateRandomIntIntRange(int min, int max) {

        Random r = new Random();
        int l = r.nextInt((max - min) + 1) + min;

        return Long.valueOf(l);
    }
}

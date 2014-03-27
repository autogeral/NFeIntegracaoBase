package br.com.jcomputacao.nfe;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Murilo
 */
public class ChaveAcesso {
    public static final NumberFormat DIGITO_FORMAT = NumberFormat.getIntegerInstance();
    public static final NumberFormat DATA_MODELO_FORMAT = NumberFormat.getIntegerInstance();
    public static final NumberFormat SERIE_FORMAT = NumberFormat.getIntegerInstance();
    public static final NumberFormat NUMERO_DOCUMENTO = NumberFormat.getIntegerInstance();
    public static final NumberFormat NUMERO_CODIGO_NUMERICO_FORMAT = NumberFormat.getIntegerInstance();
    public static final NumberFormat NUMERO_CODIGO_NUMERICO_OLD_FORMAT = NumberFormat.getIntegerInstance();
    public static final NumberFormat DOCUMENTO_FORMAT = NumberFormat.getIntegerInstance();
    public static final int TAMANHO_CHAVE = 44;
    private static int[] PESO_A = { 3, 2, 2, 2, 2, 2, 2, 2, 3 };
    private static int[] PESO_B = { 3, 2, 2, 2, 2, 2, 2, 2, 2, 3 };
    private final String uf;
    private final String ano;
    private final String mes;
    private final String emitente;
    private final String modelo;
    private final String serie;
    private final String numero;
    private final String digito;
    private final String tipoEmissao;
    private final String codigoNumerico;

    static {
	DIGITO_FORMAT.setMinimumIntegerDigits(1);
        DIGITO_FORMAT.setMaximumIntegerDigits(1);
        DIGITO_FORMAT.setGroupingUsed(false);

        DATA_MODELO_FORMAT.setMinimumIntegerDigits(2);
        DATA_MODELO_FORMAT.setMaximumIntegerDigits(2);
        DATA_MODELO_FORMAT.setGroupingUsed(false);

        SERIE_FORMAT.setMinimumIntegerDigits(3);
        SERIE_FORMAT.setMaximumIntegerDigits(3);
        SERIE_FORMAT.setGroupingUsed(false);

        NUMERO_DOCUMENTO.setMinimumIntegerDigits(9);
        NUMERO_DOCUMENTO.setMaximumIntegerDigits(9);
        NUMERO_DOCUMENTO.setGroupingUsed(false);

        NUMERO_CODIGO_NUMERICO_OLD_FORMAT.setMinimumIntegerDigits(9);
        NUMERO_CODIGO_NUMERICO_OLD_FORMAT.setMaximumIntegerDigits(9);
        NUMERO_CODIGO_NUMERICO_OLD_FORMAT.setGroupingUsed(false);

        NUMERO_CODIGO_NUMERICO_FORMAT.setMinimumIntegerDigits(8);
        NUMERO_CODIGO_NUMERICO_FORMAT.setMaximumIntegerDigits(8);
        NUMERO_CODIGO_NUMERICO_FORMAT.setGroupingUsed(false);

        DOCUMENTO_FORMAT.setMinimumIntegerDigits(14);
        DOCUMENTO_FORMAT.setMaximumIntegerDigits(14);
        DOCUMENTO_FORMAT.setGroupingUsed(false);
    }

    public ChaveAcesso(String chave) {
        if(chave==null || chave.length()!=44) {
            throw new IllegalArgumentException("Chave invalida "+chave);
        }
        //12345678901234567890123456789012345678901234
        //UUAAMMDDDDDDDDDDDDDDmmsssNNNNNNNNNTCCCCCCCCd
        int i = 0;
        uf = chave.substring(i, i+DATA_MODELO_FORMAT.getMinimumIntegerDigits());
        i+=DATA_MODELO_FORMAT.getMinimumIntegerDigits();
        ano = chave.substring(i, i+DATA_MODELO_FORMAT.getMinimumIntegerDigits());
        i+=DATA_MODELO_FORMAT.getMinimumIntegerDigits();
        mes = chave.substring(i, i+DATA_MODELO_FORMAT.getMinimumIntegerDigits());
        i+=DATA_MODELO_FORMAT.getMinimumIntegerDigits();
        emitente = chave.substring(i, i+DOCUMENTO_FORMAT.getMinimumIntegerDigits());
        i+=DOCUMENTO_FORMAT.getMinimumIntegerDigits();

        modelo = chave.substring(i, i+DATA_MODELO_FORMAT.getMinimumIntegerDigits());
        i+=DATA_MODELO_FORMAT.getMinimumIntegerDigits();

        serie = chave.substring(i, i+SERIE_FORMAT.getMinimumIntegerDigits());
        i+=SERIE_FORMAT.getMinimumIntegerDigits();

        numero = chave.substring(i, i+NUMERO_DOCUMENTO.getMinimumIntegerDigits());
        i+=NUMERO_DOCUMENTO.getMinimumIntegerDigits();

        tipoEmissao = chave.substring(i, i+DIGITO_FORMAT.getMinimumIntegerDigits());
        i+=DIGITO_FORMAT.getMinimumIntegerDigits();

        codigoNumerico = chave.substring(i, i+NUMERO_CODIGO_NUMERICO_FORMAT.getMinimumIntegerDigits());
        i+=NUMERO_CODIGO_NUMERICO_FORMAT.getMinimumIntegerDigits();

        digito = chave.substring(i, i+DIGITO_FORMAT.getMinimumIntegerDigits());
        i+=DIGITO_FORMAT.getMinimumIntegerDigits();
    }


//    public static String obterChave(TNFe nfe) {
//        Ide id = nfe.getInfNFe().getIde();
//        String ufEmitente = id.getCUF();
//        String emissao = id.getDEmi();
//        String anoEmissao = emissao.substring(0, 4);
//        String mesEmissao = emissao.substring(5, 7);
//        String documentoEmitente = nfe.getInfNFe().getEmit().getCNPJ();
//        String modelo = id.getMod();
//        String serie = id.getSerie();
//        String numero = id.getNNF();
//        String tipoEmissa = id.getTpEmis();
//        String codigoNumerico = id.getCNF();
//        String ca = gerarChaveAcesso(ufEmitente, anoEmissao, mesEmissao,
//                documentoEmitente, modelo, serie, numero, tipoEmissa, codigoNumerico);
//        ca += gerarDigitoChaveAcesso(ca);
//        return ca;
//    }

    public String getAno() {
        return ano;
    }

    public String getTipoEmissao() {
        return tipoEmissao;
    }

    public String getCodigoNumerico() {
        return codigoNumerico;
    }

    public String getDigito() {
        return digito;
    }

    public String getEmitente() {
        return emitente;
    }

    public String getMes() {
        return mes;
    }

    public String getModelo() {
        return modelo;
    }

    public String getNumero() {
        return numero;
    }

    public String getSerie() {
        return serie;
    }

    public String getUf() {
        return uf;
    }

    public static boolean verificarDigitoChaveAcesso(String chaveAcesso) {
	if (chaveAcesso == null || chaveAcesso.length() != 44)
	    return false;
	String digito = gerarDigitoChaveAcesso(chaveAcesso);
	return digito.equals(chaveAcesso.substring(43));
    }

    public static String gerarChaveAcesso(String ufEmitente, String anoEmissao, String mesEmissao,
            String documentoEmitente, String modelo, String serie, String numero, String tipoEmissao,
            String codigoNumerico, String digito) {
        return gerarChaveAcesso(ufEmitente, anoEmissao, mesEmissao,
            documentoEmitente, modelo, serie, numero, tipoEmissao,
            codigoNumerico)+(DIGITO_FORMAT.format(Long.parseLong(digito)));
    }

    public static String gerarChaveAcesso
	(String ufEmitente, String anoEmissao, String mesEmissao,
	 String documentoEmitente, String modelo, String serie, String numero,
         String tipoEmissao,
	 String codigoNumerico) {
	StringBuilder chaveAcesso = new StringBuilder();
        chaveAcesso.append(DATA_MODELO_FORMAT.format(Long.parseLong(ufEmitente)));
        chaveAcesso.append(DATA_MODELO_FORMAT.format(Long.parseLong(anoEmissao)));
        chaveAcesso.append(DATA_MODELO_FORMAT.format(Long.parseLong(mesEmissao)));
        chaveAcesso.append(DOCUMENTO_FORMAT.format(Long.parseLong(documentoEmitente)));
        chaveAcesso.append(DATA_MODELO_FORMAT.format(Long.parseLong(modelo)));
        chaveAcesso.append(SERIE_FORMAT.format(Long.parseLong(serie)));
        chaveAcesso.append(NUMERO_DOCUMENTO.format(Long.parseLong(numero)));
        chaveAcesso.append(DIGITO_FORMAT.format(Long.parseLong(tipoEmissao)));
        chaveAcesso.append(NUMERO_CODIGO_NUMERICO_FORMAT.format(Long.parseLong(codigoNumerico)));
        return chaveAcesso.toString();
    }

    public static String gerarDigitoChaveAcesso(String chaveAcesso) {
	String chaveFiltrada = chaveAcesso.replaceAll("\\D", "");
	int primeiro_digito = 0;
	int calculo = (Integer.parseInt(chaveFiltrada.substring(0, 1)) * 4
		       + Integer.parseInt(chaveFiltrada.substring(1, 2)) * 3
		       + Integer.parseInt(chaveFiltrada.substring(2, 3)) * 2
		       + Integer.parseInt(chaveFiltrada.substring(3, 4)) * 9
		       + Integer.parseInt(chaveFiltrada.substring(4, 5)) * 8
		       + Integer.parseInt(chaveFiltrada.substring(5, 6)) * 7
		       + Integer.parseInt(chaveFiltrada.substring(6, 7)) * 6
		       + Integer.parseInt(chaveFiltrada.substring(7, 8)) * 5
		       + Integer.parseInt(chaveFiltrada.substring(8, 9)) * 4
		       + Integer.parseInt(chaveFiltrada.substring(9, 10)) * 3
		       + Integer.parseInt(chaveFiltrada.substring(10, 11)) * 2
		       + Integer.parseInt(chaveFiltrada.substring(11, 12)) * 9
		       + Integer.parseInt(chaveFiltrada.substring(12, 13)) * 8
		       + Integer.parseInt(chaveFiltrada.substring(13, 14)) * 7
		       + Integer.parseInt(chaveFiltrada.substring(14, 15)) * 6
		       + Integer.parseInt(chaveFiltrada.substring(15, 16)) * 5
		       + Integer.parseInt(chaveFiltrada.substring(16, 17)) * 4
		       + Integer.parseInt(chaveFiltrada.substring(17, 18)) * 3
		       + Integer.parseInt(chaveFiltrada.substring(18, 19)) * 2
		       + Integer.parseInt(chaveFiltrada.substring(19, 20)) * 9
		       + Integer.parseInt(chaveFiltrada.substring(20, 21)) * 8
		       + Integer.parseInt(chaveFiltrada.substring(21, 22)) * 7
		       + Integer.parseInt(chaveFiltrada.substring(22, 23)) * 6
		       + Integer.parseInt(chaveFiltrada.substring(23, 24)) * 5
		       + Integer.parseInt(chaveFiltrada.substring(24, 25)) * 4
		       + Integer.parseInt(chaveFiltrada.substring(25, 26)) * 3
		       + Integer.parseInt(chaveFiltrada.substring(26, 27)) * 2
		       + Integer.parseInt(chaveFiltrada.substring(27, 28)) * 9
		       + Integer.parseInt(chaveFiltrada.substring(28, 29)) * 8
		       + Integer.parseInt(chaveFiltrada.substring(29, 30)) * 7
		       + Integer.parseInt(chaveFiltrada.substring(30, 31)) * 6
		       + Integer.parseInt(chaveFiltrada.substring(31, 32)) * 5
		       + Integer.parseInt(chaveFiltrada.substring(32, 33)) * 4
		       + Integer.parseInt(chaveFiltrada.substring(33, 34)) * 3
		       + Integer.parseInt(chaveFiltrada.substring(34, 35)) * 2
		       + Integer.parseInt(chaveFiltrada.substring(35, 36)) * 9
		       + Integer.parseInt(chaveFiltrada.substring(36, 37)) * 8
		       + Integer.parseInt(chaveFiltrada.substring(37, 38)) * 7
		       + Integer.parseInt(chaveFiltrada.substring(38, 39)) * 6
		       + Integer.parseInt(chaveFiltrada.substring(39, 40)) * 5
		       + Integer.parseInt(chaveFiltrada.substring(40, 41)) * 4
		       + Integer.parseInt(chaveFiltrada.substring(41, 42)) * 3
		       + Integer.parseInt(chaveFiltrada.substring(42, 43)) * 2);
        int novoCalculo = 0;
        int fator = 4;

        for(int i=0;i<43;i++){
            int valorString = Integer.parseInt(chaveFiltrada.substring(i, (i+1)));

            novoCalculo += valorString*fator;
            //Calcula so para proxima iteracao
            if(fator<=2){
                fator = 9;
            } else {
                fator--;
            }

        }
        if(novoCalculo!=calculo){
            System.out.println("Novo calculo diferente do calculo antigo : "+novoCalculo+" antigo: "+calculo);
        }else{
            System.out.println("Novo calculo igual ao calculo antigo : "+novoCalculo);
        }
	if (calculo < 11)
	    primeiro_digito = 11 - calculo;
	else if (calculo % 11 <= 1)
	    primeiro_digito = 0;
	else
	    primeiro_digito = 11 - calculo % 11;
	return String.valueOf(primeiro_digito);
    }

    public static String gerarCodigoNumerico(String xml) {
	MessageDigest sha = null;
	try {
	    sha = MessageDigest.getInstance("SHA-1");
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.ALL, "Erro ao obter MessageDigest", ex);
	}
        String conteudo = (String) br.com.jcomputacao.nfe.XmlUtil.getTagConteudo(xml, "infNFe", false).get(0);
	byte[] notaFiscalHash = sha.digest((conteudo).getBytes());
	long codigoNumerico = 0L;
	int hashIndex = 0;
	for (int i = 0; i < PESO_A.length; i++) {
	    byte[] algarismoBytes
		= Arrays.copyOfRange(notaFiscalHash, hashIndex,
				     hashIndex + PESO_A[i]);
	    int somaBytes = soma(algarismoBytes);
	    int algarismo = mod10(somaBytes);
	    codigoNumerico += (double) algarismo * Math.pow(10.0, (double) i);
	    hashIndex += PESO_A[i];
	}
	return NUMERO_CODIGO_NUMERICO_FORMAT.format(codigoNumerico);
    }

    public static String gerarCodigoNumericoAntigo(String xml) {
	MessageDigest sha = null;
	try {
	    sha = MessageDigest.getInstance("SHA-1");
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.ALL, "Erro ao obter MessageDigest", ex);
	}
        String conteudo = (String) br.com.jcomputacao.nfe.XmlUtil.getTagConteudo(xml, "infNFe", false).get(0);
	byte[] notaFiscalHash = sha.digest((conteudo).getBytes());
	long codigoNumerico = 0L;
	int hashIndex = 0;
	for (int i = 0; i < PESO_B.length; i++) {
	    byte[] algarismoBytes
		= Arrays.copyOfRange(notaFiscalHash, hashIndex,
				     hashIndex + PESO_B[i]);
	    int somaBytes = soma(algarismoBytes);
	    int algarismo = mod10(somaBytes);
	    codigoNumerico += (double) algarismo * Math.pow(10.0, (double) i);
	    hashIndex += PESO_B[i];
	}
	return NUMERO_CODIGO_NUMERICO_OLD_FORMAT.format(codigoNumerico);
    }

    private static int mod10(int numero) {
	int numeroAtual = numero;
	int somaAtual = 0;
	for (/**/; numeroAtual > 0; numeroAtual /= 10)
	    somaAtual += numeroAtual % 10;
	if (somaAtual / 10 > 0)
	    return mod10(somaAtual);
	return somaAtual;
    }

    private static int soma(byte[] bytes) {
	int soma = 0;
	for (int i = 0; i < bytes.length; i++)
	    soma += bytes[i];
	return soma;
    }

}

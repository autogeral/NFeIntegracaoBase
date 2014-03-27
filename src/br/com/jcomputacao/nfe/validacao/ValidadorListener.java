package br.com.jcomputacao.nfe.validacao;

import java.util.ArrayList;
import java.util.List;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXParseException;

/**
 * 11/03/2011 00:46:37
 * @author Murilo
 */
public class ValidadorListener implements ErrorHandler {
    private List<SAXParseException> erros    = new ArrayList<SAXParseException>();
    private List<SAXParseException> fatals   = new ArrayList<SAXParseException>();
    private List<SAXParseException> warnings = new ArrayList<SAXParseException>();

    @Override
    public void error(SAXParseException exception) {
        erros.add(exception);
    }

    @Override
    public void fatalError(SAXParseException exception) {
        fatals.add(exception);
    }

    @Override
    public void warning(SAXParseException exception) {
        warnings.add(exception);
    }

    public List<SAXParseException> getErros() {
        return erros;
    }

    public List<SAXParseException> getFatals() {
        return fatals;
    }

    public List<SAXParseException> getWarnings() {
        return warnings;
    }

    public boolean semErros() {
        return (erros.isEmpty() && fatals.isEmpty());
    }
}

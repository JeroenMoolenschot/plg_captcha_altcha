<?php
/*
 * @package     plg_captcha_altcha
 * @copyright   (C) 2025 Akeeba Ltd
 * @license     GPL-3.0+
 */

namespace Akeeba\Plugin\Captcha\Altcha\Extension;

defined('_JEXEC') || die;

use AltchaOrg\Altcha\Algorithm;
use AltchaOrg\Altcha\Altcha as AltchaApi;
use AltchaOrg\Altcha\ChallengeOptions;
use DateInterval;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Application\CMSWebApplicationInterface;
use Joomla\CMS\Date\Date;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Field\CaptchaField;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Event\DispatcherInterface;
use Joomla\Session\SessionInterface;
use JsonException;

/**
 * Implements the self-hosted ALTCHA as a Joomla! CAPTCHA plugin.
 *
 * @since  1.0.0
 */
final class Altcha extends CMSPlugin
{
	/** @inheritDoc */
	public function __construct(DispatcherInterface $dispatcher, array $config = [], CMSApplication $app = null)
	{
		parent::__construct($dispatcher, $config);

		$this->setApplication($app);
		$this->processExpiration();
	}

	/**
	 * Initialises the CAPTCHA plugin.
	 *
	 * @param   string  $id  The id of the field.
	 *
	 * @return  bool  True on success (always).
	 * @since   1.0.0
	 */
	public function onInit(string $id = 'altcha_1'): bool
	{
		$app = $this->getApplication();

		if (!$app instanceof CMSWebApplicationInterface)
		{
			return false;
		}

		$wam = $app->getDocument()->getWebAssetManager();

		if (!$wam->getRegistry()->exists('preset', 'plg_captcha_altcha.altcha'))
		{
			$wam->getRegistry()->addExtensionRegistryFile('plg_captcha_altcha');
		}

		$wam
			->usePreset('plg_captcha_altcha.altcha');

		return true;
	}

	/**
	 * Get the HTML for the ALTCHA field.
	 *
	 * @param   string|null  $name   The control name.
	 * @param   string       $id     The id for the control.
	 * @param   string       $class  Value for the HTML class attribute
	 *
	 * @return  string  The HTML to render the ALTCHA
	 * @since   1.1.0
	 */
	public function onDisplay(
		?string $name = null, string $id = 'altcha_1', string $class = ''
	): string
	{
		$keyHash       = hash('sha256', $id);
		$autoMode      = $this->params->get('auto', 'onsubmit');
		$hashAlgorithm = $this->params->get('hash', Algorithm::SHA512);
		$maxNumber     = $this->params->get('maxnumber', 50000);
		$saltLength    = $this->params->get('saltlength', 16);
		$expires       = $this->params->get('expires', 'PT1H');
		$delay         = $this->params->get('delay', 0);
		$hideFooter    = $this->params->get('hidefooter', 0) == 1;
		$hideLogo      = $this->params->get('hidelogo', 0) == 1;

		$options       = new ChallengeOptions(
			[
				'algorithm'  => $hashAlgorithm,
				'saltLength' => $saltLength,
				'hmacKey'    => $this->getApplication()->get('secret'),
				'maxNumber'  => $maxNumber,
				'expires'    => Date::getInstance()->add(new DateInterval($expires)),
				'params'     => [
					'keyHash' => $keyHash,
				],
			]
		);
		$challenge     = AltchaApi::createChallenge($options);
		$challengeJson = json_encode($challenge);

		Factory::getContainer()
			->get(SessionInterface::class)
			->set('altcha_challenge.' . $keyHash, $challengeJson);

		$this->loadLanguage('plg_captcha_altcha');

		// TODO style="..." for custom CSS variables

		$htmlAttributes = [
			'name'          => $name,
			'id'            => $id,
			'class'         => $class,
			'challengejson' => $challengeJson,
			'delay'         => $delay,
			'maxnumber'     => $maxNumber,
			'strings'       => json_encode(
				[
					'ariaLinkLabel' => Text::_('PLG_CAPTCHA_ALTCHA_ARIALINKLABEL'),
					'error'         => Text::_('PLG_CAPTCHA_ALTCHA_ERROR'),
					'expired'       => Text::_('PLG_CAPTCHA_ALTCHA_EXPIRED'),
					'footer'        => Text::_('PLG_CAPTCHA_ALTCHA_FOOTER'),
					'label'         => Text::_('PLG_CAPTCHA_ALTCHA_LABEL'),
					'verified'      => Text::_('PLG_CAPTCHA_ALTCHA_VERIFIED'),
					'verifying'     => Text::_('PLG_CAPTCHA_ALTCHA_VERIFYING'),
					'waitAlert'     => Text::_('PLG_CAPTCHA_ALTCHA_WAITALERT'),
				]
			),
			'hidefooter'    => (bool) $hideFooter,
			'hidelogo'      => (bool) $hideLogo,
			'auto'          => $autoMode,
		];

		return sprintf(
			"<altcha-widget %s></altcha-widget>",
			$this->arrayToString($htmlAttributes)
		);
	}

	/**
	 * Checks if the answer is correct.
	 *
	 * @param   string|null  $code  The answer.
	 *
	 * @return  bool
	 * @since   1.0.0
	 */
	public function onCheckAnswer(?string $code = null): bool
	{
		// We need a solution to work with.
		if (empty(trim($code ?? '')))
		{
			return false;
		}

		try
		{
			$code = @base64_decode($code);
		}
		catch (\Exception $e)
		{
			$code = null;
		}

		if (empty($code))
		{
			return false;
		}

		// The solution must be a JSON-encoded object with a `salt` property.
		try
		{
			$decoded = @json_decode($code, flags: JSON_THROW_ON_ERROR);
		}
		catch (JsonException $e)
		{
			$decoded = null;
		}

		if (!is_object($decoded) || !isset($decoded->salt) || !isset($decoded->number))
		{
			return false;
		}

		// Extract the custom `keyHash` parameter from the salt
		$parts = explode('?', $decoded->salt, 2);

		if (count($parts) < 2)
		{
			return false;
		}

		@parse_str($parts[1], $params);

		if (!is_array($params) || !isset($params['keyHash']) || empty($params['keyHash']))
		{
			return false;
		}

		// The keyHash must exist in the session
		/** @var SessionInterface $session */
		$session   = Factory::getContainer()->get(SessionInterface::class);
		$challenge = $session->get('altcha_challenge.' . $params['keyHash'], null);

		if (empty($challenge))
		{
			return false;
		}

		// Remove the challenge from the session, thus preventing reuse.
		$session->remove('altcha_challenge.' . $params['keyHash']);

		// Make sure the in-session challenge is valid
		try
		{
			$challenge = @json_decode($challenge, flags: JSON_THROW_ON_ERROR);
		}
		catch (JsonException $e)
		{
			$challenge = null;
		}

		if (
			!is_object($challenge)
		    || !isset($challenge->algorithm) || empty($challenge->algorithm)
		       || !isset($challenge->challenge) || empty($challenge->challenge)
		       || !isset($challenge->salt) || empty($challenge->salt)
		       || !isset($challenge->signature) || empty($challenge->signature))
		{
			return false;
		}

		// TODO Check that the communicated algorithm, challenge, salt, and signature are valid

		// Verify the solution
		return AltchaApi::verifySolution(
			[
				'algorithm' => $challenge->algorithm,
				'challenge' => $challenge->challenge,
				'number'    => $decoded->number,
				'salt'      => $challenge->salt,
				'signature' => $challenge->signature,
			],
			$this->getApplication()->get('secret'),
			true
		);
	}

	/**
	 * Modify the CAPTCHA field if necesary when it's being set up in the form.
	 *
	 * @param   CaptchaField       $field    Captcha field instance
	 * @param   \SimpleXMLElement  $element  XML form definition
	 *
	 * @return  void
	 * @since   1.0.0
	 */
	public function onSetupField(CaptchaField $field, \SimpleXMLElement $element)
	{
		// No-op, for now.
	}

	/**
	 * Processes the expiration of challenges stored in the session.
	 *
	 * @return  void
	 * @since   1.0.0
	 */
	private function processExpiration(): void
	{
		/** @var SessionInterface $session */
		$session    = Factory::getContainer()->get(SessionInterface::class);
		$challenges = $session->get('altcha_challenge');

		if (empty($challenges) || (!is_array($challenges) && !is_object($challenges)))
		{
			return;
		}

		$challenges = (array) $challenges;

		foreach ($challenges as $key => $challenge)
		{
			try
			{
				$decoded = @json_decode($challenge, flags: JSON_THROW_ON_ERROR);
			}
			catch (JsonException $e)
			{
				$decoded = null;
			}

			if (!is_object($decoded) || !isset($decoded->salt) || empty($decoded->salt))
			{
				$session->remove('altcha_challenge.' . $key);

				continue;
			}

			@parse_str($decoded->salt, $params);

			// Skip over never-expiring challenges
			if (!isset($params['expires']) || empty($params['expires']) || !is_int($params['expires']))
			{
				continue;
			}

			$date = new Date('@' . $params['expires']);

			if ($date->toUnix() < time())
			{
				$session->remove('altcha_challenge.' . $key);

				continue;
			}
		}
	}

	/**
	 * Create a string out of an array.
	 *
	 * This is used to create HTML element attributes out of an associative array.
	 *
	 * It's adapted from Joomla's \Joomla\Utilities\ArrayHelper::toString with a few changes made:
	 * - The attribute value goes through `htmlentities()` to escape double quotes.
	 * - Boolean values control whether the key appears in the list of attributes without a value
	 *
	 * @param   array    $array         The array to map.
	 * @param   string   $innerGlue     The glue (optional, defaults to '=') between the key and the value.
	 * @param   string   $outerGlue     The glue (optional, defaults to ' ') between array elements.
	 * @param   boolean  $keepOuterKey  True if an array value's key should be output verbatim.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	private function arrayToString(array $array, string $innerGlue = '=', string $outerGlue = ' ', $keepOuterKey = false
	)
	{
		$output = [];

		foreach ($array as $key => $item)
		{
			if (\is_array($item))
			{
				if ($keepOuterKey)
				{
					$output[] = $key;
				}

				// This is value is an array, go and do it again!
				$output[] = $this->arrayToString($item, $innerGlue, $outerGlue, $keepOuterKey);
			}
			elseif (is_bool($item))
			{
				if ($item)
				{
					$output[] = $key;
				}
			}
			else
			{
				$output[] = $key . $innerGlue .
				            '"' . htmlentities($item, ENT_COMPAT | ENT_HTML5, 'UTF-8') . '"';
			}
		}

		return implode($outerGlue, $output);
	}

}